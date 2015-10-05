#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <linux/seqlock.h>
#include <linux/bootmem.h>
#include <linux/sched.h>

#include "../internal.h"
#include "internal.h"

static struct kmem_cache *deep_dentry_cache __read_mostly;

static void __d_free_deep_rcu(struct rcu_head *head)
{
	struct deep_dentry *ddentry =
			container_of(head, struct deep_dentry, d_rcu);
	kmem_cache_free(deep_dentry_cache, ddentry);
}

static void __d_free_deep(struct deep_dentry *ddentry)
{
	if (!(ddentry->d_fast.d_flags & DCACHE_RCUACCESS))
		__d_free_deep_rcu(&ddentry->d_rcu);
	else
		call_rcu(&ddentry->d_rcu, __d_free_deep_rcu);
}

void __dput_deep(struct deep_dentry *ddentry)
{
	if (lockref_put_or_lock(&ddentry->d_lockref))
		return;

	lockref_mark_dead(&ddentry->d_lockref);

	list_del(&ddentry->d_fast.d_deep);
	spin_unlock(&ddentry->d_lock);

	/* time to free it */
	__d_free_deep(ddentry);
}

void __d_shrink_deep(struct fast_dentry *fdentry)
{
	struct deep_dentry *ddentry, *n;

	list_for_each_entry_safe(ddentry, n, &fdentry->d_deep, d_fast.d_deep) {
		__d_shrink_fast(&ddentry->d_fast);
		__dput_deep(ddentry);
	}
}

void d_shrink_deep(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	__d_shrink_deep(&dentry->d_fast);
	spin_unlock(&dentry->d_lock);
}

static struct deep_dentry *
__d_alloc_deep(struct dentry *root, u32 prefix_key, unsigned prefix_seq,
	       path_signature_t *signature, unsigned type)
{
	struct fast_dentry *fdentry;
	struct deep_dentry *ddentry;

	ddentry = kmem_cache_alloc(deep_dentry_cache, GFP_ATOMIC);

	if (!ddentry)
		return ddentry;

	fdentry = &ddentry->d_fast;
	d_init_fast(fdentry);
	fdentry->d_flags = type;
	fdentry->d_signature = *signature;
	ddentry->d_root = &root->d_fast;
	ddentry->d_lockref.count = 1;
	spin_lock_init(&ddentry->d_lock);

	INIT_LIST_HEAD(&fdentry->d_deep);
	spin_lock(&root->d_lock);
	list_add(&fdentry->d_deep, &root->d_fast.d_deep);
	spin_unlock(&root->d_lock);

	return ddentry;
}

static struct deep_dentry *
__d_lookup_deep_rcu(path_signature_t *signature, struct hlist_bl_head *head)
{
	struct fast_dentry *fdentry;
	struct hlist_bl_node *node;

	hlist_bl_for_each_entry_rcu(fdentry, node, head, d_hash)
	{
		unsigned seq;

		if (!(ACCESS_ONCE(fdentry->d_flags) & DCACHE_DEEP_DENTRY))
			continue;

seqretry:
		seq = raw_seqcount_begin(&fdentry->d_seq);
		if (d_unhashed_fast(fdentry))
			continue;

		if (signature_cmp(&fdentry->d_signature, signature))
			continue;

		if (read_seqcount_retry(&fdentry->d_seq, seq)) {
			cpu_relax();
			goto seqretry;
		}

		return real_deep_dentry(fdentry);
	}

	return NULL;
}

static struct deep_dentry *
__d_lookup_deep(path_signature_t *signature, struct hlist_bl_head *head)
{
	struct fast_dentry *fdentry;
	struct deep_dentry *ddentry, *found = NULL;
	struct hlist_bl_node *node;

	rcu_read_lock();

	hlist_bl_for_each_entry_rcu(fdentry, node, head, d_hash)
	{
		if (!(ACCESS_ONCE(fdentry->d_flags) & DCACHE_DEEP_DENTRY))
			continue;

		ddentry = real_deep_dentry(fdentry);
		spin_lock(&ddentry->d_lock);
		if (d_unhashed_fast(fdentry))
			goto next;

		if (signature_cmp(&fdentry->d_signature, signature))
			goto next;

		ddentry->d_lockref.count++;
		found = ddentry;
next:
		spin_unlock(&ddentry->d_lock);
	}
	rcu_read_unlock();

	return found;
}


static void
__d_update_deep(struct deep_dentry *ddentry, u32 prefix, unsigned prefix_seq,
		path_signature_t *signature,
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		path_signature_t *link_signature,
#endif
		unsigned deep_type)
{
	struct fast_dentry *fdentry = &ddentry->d_fast;

	spin_lock(&ddentry->d_lock);
	BUG_ON((fdentry->d_flags & DCACHE_DEEP_DENTRY) != deep_type);

	if (likely(fdentry->d_prefix == prefix &&
		   fdentry->d_prefix_seq == prefix_seq)) {
		spin_unlock(&ddentry->d_lock);
		return;
	}

	write_seqcount_begin(&fdentry->d_seq);

	if (signature_cmp(&fdentry->d_signature, signature)) {
		if (!d_unhashed_fast(fdentry))
			__d_shrink_fast(fdentry);

		fdentry->d_signature = *signature;
	}

	fdentry->d_prefix = prefix;
	fdentry->d_prefix_seq = prefix_seq;
	fdentry->d_mount = NULL;

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	if (link_signature)
		fdentry->d_link_signature = *link_signature;
#endif

	if (d_unhashed_fast(fdentry))
		_d_rehash_fast(fdentry);

	write_seqcount_end(&fdentry->d_seq);
	spin_unlock(&ddentry->d_lock);
}

static inline unsigned long find_name(const char *name)
{
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		c = (unsigned char)name[len];
	} while (c && c != '/');

	return len;
}

int alloc_deep_dentries(struct nameidata *nd, const char **nameptr,
			unsigned deep_type)
{
	struct dentry *dentry = nd->path.dentry;
	path_signature_t *signature = &nd->fast.signature;
	const unsigned char *name = (const unsigned char *) *nameptr;
#ifdef CONFIG_DCACHE_FORCE_CANONICAL
	const unsigned char *start = name;
	struct qstr last = { .name = NULL, .len = 0 };
#endif
	int err = 0;

	if (unlikely(!(nd->flags & LOOKUP_CACHE_FAST)))
		return 0;

	if (unlikely(ACCESS_ONCE(dentry->d_flags) & DCACHE_OP_REVALIDATE)) {
		terminate_walk_fast(nd);
		return 0;
	}

	while (*name == '/')
		name++;
	if (!*name)
		return 0;

	for(;;) {
		const unsigned char *s;
		unsigned int c;
		long len;
		struct qstr this;
		int type;

		s = name;
		len = find_name(name);
		c = *(name += len);
		this.name = s;
		this.len = len;

		type = LAST_NORM;
		if (s[0] == '.') switch (len) {
			case 2:
				if (s[1] == '.')
					type = LAST_DOTDOT;
				break;
			case 1:
				type = LAST_DOT;
		}

		if (c)
			while ((c = *++name) == '/');

		if (likely(type == LAST_NORM)) {
			struct deep_dentry *ddentry = NULL;
			struct hlist_bl_head *bl;

			partial_signature(signature, s, len);
			bl = d_hash_fast(signature);

			ddentry = (nd->flags & LOOKUP_RCU) ?
				__d_lookup_deep_rcu(signature, bl) :
				__d_lookup_deep(signature, bl);

			if (ddentry) {
				__d_update_deep(ddentry, nd->fast.prefix,
						nd->fast.prefix_seq,
						signature,
#ifdef CONFIG_DCACHE_FAST_SYMLINK
						NULL,
#endif
						deep_type);

				if (!(nd->flags & LOOKUP_RCU))
					__dput_deep(ddentry);
				goto done_component;
			}

			ddentry = __d_alloc_deep(dentry,
						 nd->fast.prefix,
						 nd->fast.prefix_seq,
						 signature,
						 deep_type);
			if (!ddentry) {
				err = -ENOMEM;
				break;
			}

			spin_lock(&ddentry->d_lock);
			__d_rehash_fast(&ddentry->d_fast, bl);
			spin_unlock(&ddentry->d_lock);
		} else if (type == LAST_DOTDOT) {
#ifdef CONFIG_DCACHE_FORCE_CANONICAL
			if (!last.len) {
				if (nd->flags & LOOKUP_RCU) {
					if (follow_dotdot_rcu(nd)) {
						err = -EAGAIN;
						break;
					}
				} else {
					follow_dotdot(nd);
				}

				nd->last = this;
				nd->last.hash =
					full_name_hash(this.name, this.len);
				nd->last_type = type;
				*nameptr = (const char *) name;
				return 1;
			}

			reverse_signature(signature, last.name, last.len);
			last_norm_component(&last, start);
#else
			/* if we are not forcing canonicalizing path, the
			 * dotdot will be handled on the fastpath */
			break;
#endif
		}
done_component:
		if (!c)
			break;
	}

	return err;
}

#ifdef CONFIG_DCACHE_FAST_SYMLINK
void alloc_fast_symlink(struct nameidata *nd, const char *name,
			unsigned int len, int type)
{
	if (type == LAST_NORM) {
		unsigned depth = nd->fast.nested_link_depth;
		path_signature_t *link_signature = &nd->fast.signature;
		u32 prefix_key = nd->fast.prefix;
		unsigned prefix_seq = nd->fast.prefix_seq;

		for (; depth < nd->fast.link_depth ; depth++) {
			struct link_nameidata *linknd = &nd->fast.links[depth];
			struct dentry *root = linknd->link.dentry;
			path_signature_t *signature = &linknd->signature;
			struct deep_dentry *ddentry = NULL;
			struct hlist_bl_head *bl;

			partial_signature(signature, name, len);
			bl = d_hash_fast(signature);

			ddentry = (nd->flags & LOOKUP_RCU) ?
				__d_lookup_deep_rcu(signature, bl) :
				__d_lookup_deep(signature, bl);

			if (ddentry) {
				__d_update_deep(ddentry, nd->fast.prefix,
						nd->fast.prefix_seq,
						signature,
						link_signature,
						DEEP_SYMLINK);

				if (!(nd->flags & LOOKUP_RCU))
					__dput_deep(ddentry);
			} else {
				ddentry = __d_alloc_deep(root,
							 prefix_key, prefix_seq,
							 signature,
							 DEEP_SYMLINK);

				if (unlikely(!ddentry)) {
					terminate_walk_fast(nd);
					return;
				}

				ddentry->d_fast.d_link_signature =
							*link_signature;

				spin_lock(&ddentry->d_lock);
				__d_rehash_fast(&ddentry->d_fast, bl);
				spin_unlock(&ddentry->d_lock);
			}

			link_signature = signature;
			prefix_key = linknd->prefix;
			prefix_seq = linknd->prefix_seq;
		}

		return;
	}

#ifdef CONFIG_DCACHE_FORCE_CANONICAL
	if (type == LAST_DOTDOT) {
		if (nd->fast.link_depth > nd->fast.nested_link_depth)
			terminate_walk_fast(nd);
		return;
	}
#else
	if (type == LAST_DOTDOT) {
		while (nd->fast.link_depth > nd->fast.nested_link_depth)
			path_put(&nd->fast.links[--nd->fast.link_depth].link);

		return;
	}
#endif

}
#endif

void __init deep_dentry_init(void)
{
	deep_dentry_cache = KMEM_CACHE(deep_dentry,
				       SLAB_RECLAIM_ACCOUNT|SLAB_PANIC);
}

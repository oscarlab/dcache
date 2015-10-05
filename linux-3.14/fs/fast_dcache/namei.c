/* Copyright (C) 2015 OSCAR lab, Stony Brook University

   This program is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <linux/compiler.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/audit.h>
#include <linux/ima.h>
#include <asm/word-at-a-time.h>
#include <asm/uaccess.h>
#include <linux/seqlock.h>

#include "../internal.h"
#include "../mount.h"
#include "internal.h"
#include "profiling.h"

static inline
int __path_cmp(path_signature_t *signature, path_signature_t *target)
{
	d_debug(D, "    compare signature:\n");
	d_debug(D, "      " PATH_SIGNATURE_FMT "\n",
		PATH_SIGNATURE_PRINTK(*signature));
	d_debug(D, "      " PATH_SIGNATURE_FMT "\n",
		PATH_SIGNATURE_PRINTK(*target));
	return signature_cmp(signature, target);
}

static inline
int __update_fast(struct fast_dentry *fdentry,
		  u32 prefix_key, unsigned prefix_seq, struct vfsmount *mnt,
		  struct qstr *name, path_signature_t *signature,
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		  path_signature_t *link_signature,
#endif
		  unsigned *seqp, spinlock_t *lock)
{
	unsigned seq = *seqp;

	if (likely(fdentry->d_prefix == prefix_key &&
		   fdentry->d_prefix_seq == prefix_seq)) {
		path_signature_t s = fdentry->d_signature;

#ifdef CONFIG_DCACHE_FAST_SYMLINK
		if (link_signature &&
		    !(fdentry->d_flags & DCACHE_SYMLINK_FOLLOWED))
			goto update;
#endif

		if (read_seqcount_retry(&fdentry->d_seq, seq))
			return -EAGAIN;

		*signature = s;
		d_debug(D, "  read: " PATH_SIGNATURE_FMT "\n",
			PATH_SIGNATURE_PRINTK(*signature));
		return 0;
	}

update:
	if (name) {
#ifdef CONFIG_DCACHE_DEBUG
		char last_name[name->len + 1];
		memcpy(last_name, name->name, name->len);
		last_name[name->len] = '\0';
#endif
		partial_signature(signature, name->name, name->len);

		d_debug(D, "  walk %s: " PATH_SIGNATURE_FMT "\n", last_name,
			PATH_SIGNATURE_PRINTK(*signature));
	}

	spin_lock(lock);
	write_seqcount_begin(&fdentry->d_seq);

	if (__path_cmp(&fdentry->d_signature, signature)) {
		if (!d_unhashed_fast(fdentry))
			__d_shrink_fast(fdentry);

		fdentry->d_signature = *signature;
	}

	fdentry->d_prefix = prefix_key;
	fdentry->d_prefix_seq = prefix_seq;
	fdentry->d_mount = mnt;

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	if (link_signature) {
		fdentry->d_flags |= DCACHE_SYMLINK_FOLLOWED;
		fdentry->d_link_signature = *link_signature;
		d_debug(D, "  link: " PATH_SIGNATURE_FMT "\n",
			PATH_SIGNATURE_PRINTK(fdentry->d_link_signature));
	} else {
		fdentry->d_flags &= ~DCACHE_SYMLINK_FOLLOWED;
	}
#endif

	if (d_unhashed_fast(fdentry))
		_d_rehash_fast(fdentry);

	*seqp = fdentry->d_seq.sequence + 1;
	write_seqcount_end(&fdentry->d_seq);
	spin_unlock(lock);
	return 1;
}

#ifdef CONFIG_DCACHE_CRED_PCC

static void put_cred_pcc_rcu(struct rcu_head *rcu)
{
	struct cred_pcc *pcc = container_of(rcu, struct cred_pcc, rcu);
	kfree(pcc);
}

void __put_cred_pcc(struct cred_pcc *pcc)
{
	BUG_ON(atomic_read(&pcc->usage) != 0);
	d_debug(D, "put PCC %p\n", pcc);
	call_rcu(&pcc->rcu, put_cred_pcc_rcu);
}

struct cred_pcc *__alloc_cred_pcc(void)
{
	size_t size = sizeof(struct cred_pcc_entry) * CONFIG_CRED_PCC_SIZE *
		      CONFIG_CRED_PCC_ASSOCIATIVITY;
	struct cred_pcc *pcc =
		kmalloc(sizeof(struct cred_pcc) + size, GFP_ATOMIC);
	if (!pcc)
		return NULL;

	d_debug(D, "allocate PCC %p\n", pcc);

	atomic_set(&pcc->usage, 1);
	memset(pcc->entries, 0, size);
	return pcc;
}


#define CRED_SEED1 (0x333152d4e627c45fULL) /* must be odd */
#define CRED_SEED2 (0x921fe762ULL)

static inline
struct cred_pcc_entry *d_cred_pcc(struct cred_pcc *pcc, u32 key)
{
	u64 hash = CRED_SEED1 * key + CRED_SEED2;
	hash = (hash >> 32) & (CONFIG_CRED_PCC_SIZE - 1);
	hash *= CONFIG_CRED_PCC_ASSOCIATIVITY;
	return &pcc->entries[hash];
}

static inline
void __cache_fast(struct fast_dentry *fdentry,
		  u32 prefix_key, unsigned prefix_seq, struct vfsmount *mnt,
		  struct qstr *name, path_signature_t *signature,
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		  path_signature_t *link_signature,
#endif
		  struct dentry_info *dentry_info, spinlock_t *lock)
{
	struct cred_pcc *pcc = dentry_info->pcc;
	struct cred_pcc_entry *start, *end, *p, e, *victim = NULL;
	int error;

	start = d_cred_pcc(pcc, prefix_key);
	end = start + CONFIG_CRED_PCC_ASSOCIATIVITY;
	e.recently = 1;
	e.dentry = prefix_key;
	e.seq = prefix_seq;

	/* Now walk the pcc to match with the prefix key. We don't care about
	 * the coherence at all. */
	for (p = start; p < end ; p++) {
		u64 s = (p->raw ^ e.raw) & ~PCC_RECENTLY_MASK;

		if (likely(!s))
			goto present;
	}

	for (p = start; p < end ; p++) {
		if (unlikely(!victim && !p->recently))
			victim = p;

		p->raw &= ~PCC_RECENTLY_MASK;
	}

	if (unlikely(!victim))
		victim = start + (jiffies % CONFIG_CRED_PCC_ASSOCIATIVITY);

	d_debug(D, "  clear %08x:%08x\n", victim->dentry, victim->seq);

	victim->raw = e.raw;

present:
	do {
		unsigned seq = read_seqcount_begin(&fdentry->d_seq);
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		error = __update_fast(fdentry, prefix_key, prefix_seq, mnt,
				      name, signature, link_signature,
				      &seq, lock);
#else
		error = __update_fast(fdentry, prefix_key, prefix_seq, mnt,
				      name, signature, &seq, lock);
#endif
	} while (error == -EAGAIN);
}

#else /* CONFIG_DCACHE_CRED_PCC */

static atomic_t cid_counter = ATOMIC_INIT(0);

u32 new_cid(void)
{
	return atomic_add_return(1, &cid_counter);
}

static inline
void __cache_fast(struct fast_dentry *fdentry,
		  u32 prefix_key, unsigned prefix_seq, struct vfsmount *mnt,
		  struct qstr *name, path_signature_t *signature,
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		  path_signature_t *link_signature,
#endif
		  struct dentry_info *dentry_info, spinlock_t *lock)
{
	struct dentry_pcc *replace = NULL, *avail = NULL, *present = NULL;
	struct dentry_pcc *p;
	u32 id = 0;
	unsigned seq;
	int error;

#ifdef CONFIG_DCACHE_CRED_ID
	id = dentry_info->cid;
#else
	id = __kuid_val(current_uid()) ? : UID_ROOT;
#endif

retry:
	seq = raw_seqcount_begin(&fdentry->d_seq);

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	error = __update_fast(fdentry, prefix_key, prefix_seq, mnt, name,
			      signature, link_signature, &seq, lock);
#else
	error = __update_fast(fdentry, prefix_key, prefix_seq, mnt, name,
			      signature, &seq, lock);
#endif

	if (error == -EAGAIN)
		goto retry;

	if (error == 1) {
		e.recently = 1;
		e.cred = id;
		e.seq = seq;
		*fdentry->d_pcc = e;
		return;
	}

	for (p = fdentry->d_pcc;
	     p < &fdentry->d_pcc[CONFIG_DCACHE_PCC_SIZE]; p++) {
		if (p->seq == seq && p->cred == id) {
			present = p;
			if (!p->recently)
				p->recently = 1;
		} else {
			if (p->seq != seq) {
				if (!avail)
					avail = p;
			} else {
				if (p->recently)
					p->recently = 0;
				else if (!replace)
					replace = p;
			}
		}
	}

	if (!present) {
		if (!avail)
			avail = replace;
		if (!avail)
			avail = &fdentry->d_pcc[jiffies % CONFIG_DCACHE_PCC_SIZE];

		avail->recently = 1;
		avail->cred = id;
		avail->seq = seq;
	}
}

#endif /* !CONFIG_DCACHE_CRED_PCC */

void path_init_fast(struct nameidata *nd, const char *name)
{
	const struct cred *cred = current_cred();
	struct dentry *dentry = nd->path.dentry;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&dentry->d_fast.d_seq);
		nd->fast.prefix = d_prefix_key(&dentry->d_fast);
		nd->fast.prefix_seq = seq;
		nd->fast.signature = dentry->d_fast.d_signature;
	} while (read_seqcount_retry(&dentry->d_fast.d_seq, seq));

	nd->fast.invalidate_seq = raw_seqcount_begin(&invalidate_seq);
	nd->fast.dentry_info = cred->dentry_info;
#ifdef CONFIG_DCACHE_FAST_SYMLINK
	nd->fast.link_depth = nd->fast.nested_link_depth = 0;
#endif

	d_debug(D, "start walk: " DENTRY_NAME_FMT ": " PATH_SIGNATURE_FMT "\n",
		DENTRY_NAME_PRINTK(dentry),
		PATH_SIGNATURE_PRINTK(nd->fast.signature));

	if (nd->fast.prefix_seq == PREFIX_SEQ_INVALID &&
	    !signature_is_zero(&nd->fast.signature))
		return;

	/* don't turn of caching for fastpath in some conditions */
#ifdef CONFIG_DCACHE_CRED_CID
	if (nd->fast.dentry_info.cid == CID_INVALID)
		return;
#endif
#ifdef CONFIG_DCACHE_CRED_PCC
	if (!nd->fast.dentry_info.pcc)
		return;
#endif

	nd->flags |= LOOKUP_CACHE_FAST;
}

void walk_fast(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	nd->fast.prefix = d_prefix_key(&dentry->d_fast);
	nd->fast.prefix_seq = raw_seqcount_begin(&dentry->d_fast.d_seq);
}

void cache_fast(const struct path *path, struct nameidata *nd)
{
	if (unlikely(!(nd->flags & LOOKUP_CACHE_FAST)))
		return;

	if (read_seqcount_retry(&invalidate_seq, nd->fast.invalidate_seq)) {
		terminate_walk_fast(nd);
		return;
	}

	if (unlikely(d_unhashed(path->dentry) && !IS_ROOT(path->dentry))) {
		terminate_walk_fast(nd);
		return;
	}

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	BUG_ON(path->dentry->d_flags & DCACHE_DEEP_DENTRY);
#endif

	if (likely(nd->last_type == LAST_NORM)) {
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		__cache_fast(&path->dentry->d_fast,
			     nd->fast.prefix, nd->fast.prefix_seq, path->mnt,
			     &nd->last, &nd->fast.signature, NULL,
			     &nd->fast.dentry_info, &path->dentry->d_lock);
#else
		__cache_fast(&path->dentry->d_fast,
			     nd->fast.prefix, nd->fast.prefix_seq, path->mnt,
			     &nd->last, &nd->fast.signature,
			     &nd->fast.dentry_info, &path->dentry->d_lock);
#endif

		/* if the dentry is meant to be revalidated, no more caching */
		if (unlikely(path->dentry->d_flags & DCACHE_OP_REVALIDATE))
			terminate_walk_fast(nd);
	}

	if (likely(nd->last_type == LAST_DOTDOT))
		reset_walk_fast(nd);

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	if (unlikely(nd->fast.nested_link_depth < nd->fast.link_depth))
		alloc_fast_symlink(nd,
				   nd->last.name, nd->last.len,
				   nd->last_type);
#endif
}

#ifdef CONFIG_DCACHE_FAST_SYMLINK
void walk_fast_symlink(struct nameidata *nd, struct path *link)
{
	struct link_nameidata *linknd;

	if (unlikely(!(nd->flags & LOOKUP_CACHE_FAST)))
		return;

	if (unlikely(nd->fast.link_depth == MAX_NESTED_LINKS)) {
		terminate_walk_fast(nd);
		return;
	}

	BUG_ON(nd->last_type != LAST_NORM);

	path_get(link);
	linknd = &nd->fast.links[nd->fast.link_depth++];
	linknd->prefix = nd->fast.prefix;
	linknd->prefix_seq = nd->fast.prefix_seq;
	linknd->link = *link;
	linknd->signature = nd->fast.signature;
	partial_signature(&linknd->signature, nd->last.name, nd->last.len);
	nd->fast.nested_link_depth = nd->fast.link_depth;
}

void cache_fast_symlink(struct nameidata *nd, unsigned depth, void *cookie)
{
	struct link_nameidata *linknd, *target;
	path_signature_t *link_signature;

	if (unlikely(!(nd->flags & LOOKUP_CACHE_FAST)))
		return;

	if (cookie) {
		terminate_walk_fast(nd);
		return;
	}

	BUG_ON(!nd->fast.nested_link_depth);
	linknd = &nd->fast.links[nd->fast.nested_link_depth - 1];
	target = &nd->fast.links[nd->fast.nested_link_depth];
	link_signature = &target->signature;
	if (nd->fast.link_depth == nd->fast.nested_link_depth) {
		*link_signature = nd->fast.signature;
		partial_signature(link_signature, nd->last.name,nd->last.len);
	}

	__cache_fast(&linknd->link.dentry->d_fast,
		     linknd->prefix, linknd->prefix_seq,
		     linknd->link.mnt, NULL,
		     &linknd->signature, link_signature,
		     &nd->fast.dentry_info,
		     &linknd->link.dentry->d_lock);
}
#endif

void reset_walk_fast(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&dentry->d_fast.d_seq);
		nd->fast.signature = dentry->d_fast.d_signature;
	} while (read_seqcount_retry(&dentry->d_fast.d_seq, seq));

	d_debug(D, "  walk: " PATH_SIGNATURE_FMT "\n",
		PATH_SIGNATURE_PRINTK(nd->fast.signature));
}

void terminate_walk_fast(struct nameidata *nd)
{
	if (unlikely(!(nd->flags & LOOKUP_CACHE_FAST)))
		return;

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	while (nd->fast.link_depth)
		path_put(&nd->fast.links[--nd->fast.link_depth].link);
	nd->fast.nested_link_depth = 0;
#endif

	nd->flags &= ~LOOKUP_CACHE_FAST;
}

#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

unsigned long find_name(const char *name)
{
	unsigned long a, b, adata, bdata, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = -sizeof(unsigned long);
	do {
		len += sizeof(unsigned long);
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);

	return len + find_zero(create_zero_mask(adata | bdata));
}

#else

unsigned long find_name(const char *name)
{
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		c = (unsigned char)name[len];
	} while (c && c != '/');

	return len;
}

#endif

static inline
int link_path_walk_scan(struct nameidata *nd, const unsigned char **name)
{
	const unsigned char *string = *name, *start = string;
	path_signature_t *signature = &nd->fast.signature;
	struct qstr last = { .name = NULL, .len = 0 };
	bool need_lookup = false;
#ifndef CONFIG_DCACHE_FORCE_CANONICAL
	bool norm = false;
#endif

	/*
	 * Now we jump into a loop that interate through the path and
	 * calculate the hash value for looking up.
	 */
	for(;;) {
		const unsigned char *s;
		unsigned int c;
		long len;
		struct qstr this;
		int type;

		s = string;
		len = find_name(string);
		c = *(string += len);
		this.name = s;
		this.len = len;

		type = LAST_NORM;
		if (s[0] == '.') switch (len) {
			case 2:
				if (s[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM))
			nd->flags &= ~LOOKUP_JUMPED;

		if (c)
			while ((c = *++string) == '/');

		if (!c && (nd->flags & LOOKUP_PARENT))
			goto last_component;

		if (likely(type == LAST_NORM)) {
			partial_signature(signature, s, len);
			last = this;
			need_lookup = true;
#ifdef CONFIG_DCACHE_DEBUG_DETAIL
			{
				char buf[len + 1];
				memcpy(buf, s, len);
				buf[len] = '\0';

				d_debug(D, "  walk %s: "
					PATH_SIGNATURE_FMT "\n", buf,
					PATH_SIGNATURE_PRINTK(*signature));
			}
#endif

#ifndef CONFIG_DCACHE_FORCE_CANONICAL
			norm = true;
#endif
		} else if (type == LAST_DOTDOT) {
#ifndef CONFIG_DCACHE_FORCE_CANONICAL
			if (norm) {
				string = s;
				break;
			}
#endif
			if (!last.len) {
				if (follow_dotdot_rcu(nd))
					return -EAGAIN;
				*signature = nd->path.dentry->d_fast.d_signature;
				start = string;
				need_lookup = false;
				goto done_component;
			}

#ifdef CONFIG_DCACHE_DEBUG_DETAIL
			{
				char buf[last.len + 1];
				memcpy(buf, last.name, last.len);
				buf[last.len] = '\0';

				d_debug(D, "  walk ..(%s): "
					PATH_SIGNATURE_FMT "\n", buf,
					PATH_SIGNATURE_PRINTK(*signature));
			}
#endif

			reverse_signature(signature, last.name, last.len);
			last_norm_component(&last, start);
			this = last;
			type = LAST_NORM;
			need_lookup = true;
		}
done_component:
		if (c)
			continue;
last_component:
		nd->last = this;
		nd->last.hash = full_name_hash(this.name, this.len);
		nd->last_type = type;
		break;
	}

	*name = string;
	return need_lookup ? 1 : 0;
}

#ifdef CONFIG_DCACHE_CRED_PCC
static inline
int dentry_permission(struct fast_dentry *fdentry, struct nameidata *nd,
		      unsigned seq)
{
	struct cred_pcc *pcc = nd->fast.dentry_info.pcc;
	struct cred_pcc_entry *start, *end, *p, e;
	u32 prefix_key = fdentry->d_prefix;
	unsigned prefix_seq = fdentry->d_prefix_seq;
	int err = -EAGAIN;

	if (unlikely(nd->flags & LOOKUP_PARENT)) {
		prefix_key = d_prefix_key(fdentry);
		prefix_seq = raw_seqcount_begin(&fdentry->d_seq);
	}

	start = d_cred_pcc(pcc, prefix_key);
	end = start + CONFIG_CRED_PCC_ASSOCIATIVITY;
	e.recently = 0;
	e.dentry = prefix_key;
	e.seq = prefix_seq;

	d_debug(D, "    check PCC %p (%p-%p):\n", pcc, start, end);

	for (p = start; p < end ; p++) {
		u64 s = (p->raw ^ e.raw) & ~PCC_RECENTLY_MASK;

		d_debug(D, "      %08x:%08x\n", p->dentry, p->seq);

		if (likely(!s)) {
			err = 0;
			break;
		}
	}

	if (err)
		d_debug(D, "  check %08x:%08x miss\n", prefix_key, prefix_seq);

	return err;
}
#else /* CONFIG_DCACHE_CRED_PCC */
static inline
int dentry_permission(struct fast_dentry *fdentry, struct nameidata *nd,
		      unsigned seq)
{
	struct dentry_pcc *p;
# ifdef CONFIG_DCACHE_CRED_ID
	u32 id = nd->fast.dentry_info.cid;
# else
	u32 id = __kuid_val(current_uid()) ? : UID_ROOT;
# endif
	int err = -EAGAIN;

	for (p = fdentry->d_pcc;
	     p < &fdentry->d_pcc[CONFIG_DCACHE_PCC_SIZE]; p++) {
		if (p->seq == seq && p->cred == id) {
			err = 0;
			break;
		}
	}

	return err;
}
#endif /* !CONFIG_DCACHE_CRED_PCC */

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
static inline int walk_deep_dentry(struct fast_dentry *fdentry,
				   struct nameidata *nd, unsigned seq)
{
	struct deep_dentry *ddentry = real_deep_dentry(fdentry);
	struct fast_dentry *root = ddentry->d_root;
	unsigned type = (fdentry->d_flags & DCACHE_DEEP_DENTRY);
#ifdef CONFIG_DCACHE_FAST_SYMLINK
	path_signature_t link_signature;
#endif
	int err = 0;
	BUG_ON(!root);

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	if (type == DEEP_SYMLINK)
		link_signature = fdentry->d_link_signature;
#endif

	if (read_seqcount_retry(&fdentry->d_seq, seq))
		return 1;

seqretry:
	seq = raw_seqcount_begin(&root->d_seq);

	/* even for a deep dentry, we have to check the
	 * permission for its root dentry */
	err = dentry_permission(root, nd, seq);
	if (unlikely(err == -EAGAIN))
		return err;
	if (unlikely(err))
		goto out;

	switch(type) {
#ifdef CONFIG_DCACHE_FAST_SYMLINK
		case DEEP_SYMLINK:
			nd->fast.signature = link_signature;
			break;
#endif
#ifdef CONFIG_DCACHE_FAST_DEEP_NEGATIVE
		case DEEP_NEGATIVE:
			err = -ENOENT;
			break;
#endif
#ifdef CONFIG_DCACHE_FAST_DEEP_NOTDIR
		case DEEP_NOTDIR:
			err = -ENOTDIR;
			break;
#endif
		default:
			BUG();
			break;
	}

out:
	if (read_seqcount_retry(&root->d_seq, seq)) {
		cpu_relax();
		goto seqretry;
	}

	return err;
}
#endif

#ifdef CONFIG_DCACHE_LOOKUP_STAT
/* Collect lookup statistics. */
struct dcache_lookup_fast_stat_t dcache_lookup_fast_stat;

static DEFINE_PER_CPU(long, lookup_fast_hit);
static DEFINE_PER_CPU(long, lookup_fast_miss);

int dcache_enable_lookup_fast_stat __read_mostly = 0;

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_dcache_lookup_fast_stat(ctl_table *table, int write, void __user *buffer,
				 size_t *lenp, loff_t *ppos)
{
	int i;
	struct dcache_lookup_fast_stat_t stat = { 0, 0, };
	for_each_possible_cpu(i) {
		stat.hit	+= per_cpu(lookup_fast_hit,	i);
		stat.miss	+= per_cpu(lookup_fast_miss,	i);
	}
	dcache_lookup_fast_stat = stat;
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}

int proc_dcache_enable_lookup_fast_stat(ctl_table *table, int write,
					void __user *buffer,
					size_t *lenp, loff_t *ppos)
{
	int error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (!error && write && dcache_enable_lookup_fast_stat == 2) {
		int i;
		for_each_possible_cpu(i) {
			per_cpu(lookup_fast_hit,	i) = 0;
			per_cpu(lookup_fast_miss,	i) = 0;
		}
	}
	return error;
}
#endif

#define INC_STAT(type)							\
	do {								\
		if (dcache_enable_lookup_fast_stat)			\
			this_cpu_inc(lookup_fast_##type);		\
	} while (0)
#else
#define INC_STAT(type) do {} while (0)
#endif /* DCACHE_LOOKUP_STAT */

#if defined(CONFIG_PATH_SIGNATURE_MHASH) || defined(CONFIG_PATH_SIGNATURE_MHASH_AVX2)
#include"mhash.h"
#endif

/*
 * Our optimized version of link_path_walk. Instead of looking up the
 * dentries at each token of the path, this function generates the
 * hash of the whole path and looks it up. The optimized link_path_walk
 * is expected to return exactly same result if the lookup gets a hit,
 * otherwise it should restore the nameidata to its original value and
 * fall back to the old link_path_walk.
 */
int link_path_walk_fast(int dfd, const char *name, unsigned int flags,
			struct nameidata *nd)

{
	const unsigned char *string = (const unsigned char *) name;
	struct hlist_bl_head *bl;
	struct hlist_bl_node *node;
	struct fast_dentry *fdentry = NULL;
	struct path path;
	int err, retries = 0;
	const struct cred *cred = current_cred();
	DECLARE_TIME(total);
	DECLARE_TIME(init);
	DECLARE_TIME(scan);
	DECLARE_TIME(loop);
	DECLARE_TIME(cmp);
	DECLARE_TIME(perm);
	DECLARE_TIME(barrier);
	DECLARE_TIME(fini);
	DECLARE_TIME(follow);
#ifdef CONFIG_DCACHE_FAST_PROFILING
	unsigned walk_count = 0;
#endif

	BUG_ON(!(flags & LOOKUP_RCU));

	TIME_START(total);
	TIME_START(init);

	/*
	 * The optimized link_path_walk has to initialize the path
	 * individually before the caller does it. We have only
	 * implemented the RCU-based lookup, so we will initialize
	 * the path with LOOKUP_RCU no matter whether it's given
	 * in the flag.
	 */
	nd->last_type = LAST_ROOT;
	nd->flags = flags | LOOKUP_FAST;
	nd->depth = 0;
	nd->root.mnt = NULL;
	//nd->m_seq = read_seqbegin(&mount_lock);
	if (*name=='/') {
		struct fs_struct *fs = current->fs;
		unsigned seq;

		rcu_read_lock();

		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->path = fs->root;
			if (!(nd->flags & LOOKUP_ROOT))
				nd->root = fs->root;
		} while (read_seqcount_retry(&fs->seq, seq));
	} else if (dfd == AT_FDCWD) {
		struct fs_struct *fs = current->fs;
		unsigned seq;

		rcu_read_lock();

		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->path = fs->pwd;
			if (!(nd->flags & LOOKUP_ROOT))
				nd->root = fs->root;
		} while (read_seqcount_retry(&fs->seq, seq));
	} else {
		struct fd f = fdget_raw(dfd);
		if (!f.file)
			return -EBADF;

		nd->path = f.file->f_path;
		fdput(f);
		rcu_read_lock();
	}

	nd->fast.signature = nd->path.dentry->d_fast.d_signature;
	nd->fast.dentry_info = cred->dentry_info;
	nd->inode = nd->path.dentry->d_inode;

#if defined(CONFIG_PATH_SIGNATURE_MHASH) || defined(CONFIG_PATH_SIGNATURE_MHASH_AVX2)
	//mhash_prepare(nd->fast.signature.state);
#endif
	TIME_END(init);

	err = -EAGAIN;
#ifdef CONFIG_DCACHE_CRED_CID
	if (nd->fast.cred->dentry_info.cid == CID_INVALID)
		goto out;
#endif
#ifdef CONFIG_DCACHE_CRED_PCC
	if (!nd->fast.dentry_info.pcc)
		goto out;
#endif

	while (*string == '/')
		string++;
	if (!*string) {
		nd->flags &= ~LOOKUP_RCU;
		nd->seq = raw_seqcount_begin(&nd->path.dentry->d_seq);
		path_get(&nd->path);
		err = 0;
		goto out;
	}

rescan:
	TIME_START(scan);
	err = link_path_walk_scan(nd, &string);
	TIME_END(scan);
	if (unlikely(err == -EAGAIN))
		goto out_unlocked;
	if (unlikely(err < 0))
		goto out;

	if (!err) {
		if (retries)
			goto done;

		if (d_is_negative(nd->path.dentry)) {
			err = -ENOENT;
			goto out;
		}

		nd->flags &= ~LOOKUP_RCU;
		path_get(&nd->path);
		err = 0;
		goto out;
	}

rewalk:
	bl = d_hash_fast(&nd->fast.signature);
	TIME_START(loop);
	err = -EAGAIN;
	hlist_bl_for_each_entry_rcu(fdentry, node, bl, d_hash)
	{
		struct dentry *dentry = real_dentry(fdentry);
		struct vfsmount *mnt;
		unsigned seq;
		unsigned int d_flags;
		prefetch(&fdentry->d_signature);

		d_debug(D, "  check " DENTRY_NAME_FMT "\n",
			DENTRY_NAME_PRINTK(dentry));

#ifdef CONFIG_DCACHE_FAST_PROFILING
		walk_count++;
#endif
seqretry:
		seq = raw_seqcount_begin(&fdentry->d_seq);
		if (d_unhashed_fast(fdentry))
			continue;

		d_flags = fdentry->d_flags;
		TIME_START(cmp);
		if (__path_cmp(&fdentry->d_signature, &nd->fast.signature)) {
			TIME_END(cmp);
			continue;
		}
		TIME_END(cmp);
#ifdef CONFIG_DCACHE_FAST_FORCE_MISS
		continue;
#endif

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
		if (unlikely(d_flags & DCACHE_DEEP_DENTRY)) {
			err = walk_deep_dentry(fdentry, nd, seq);
			if (unlikely(err == -EAGAIN))
				continue;

			if (unlikely(err == 1)) {
				cpu_relax();
				goto seqretry;
			}

			if (!err) {
				TIME_END(loop);
				goto rewalk;
			}

			break;
		}
#endif

		TIME_START(perm);
		err = dentry_permission(fdentry, nd, seq);
		TIME_END(perm);
		if (unlikely(err == -EAGAIN))
			continue;

		mnt = fdentry->d_mount;
		TIME_START(barrier);
		if (read_seqcount_retry(&fdentry->d_seq, seq)) {
			cpu_relax();
			TIME_END(barrier);
			goto seqretry;
		}
		TIME_END(barrier);

		err = -EAGAIN;
		if (unlikely(d_flags & DCACHE_MANAGED_DENTRY))
			break;

		nd->seq = raw_seqcount_begin(&dentry->d_seq);;
		path.dentry = dentry;
		path.mnt = mnt;
		nd->inode = dentry->d_inode;

		switch(d_flags & DCACHE_ENTRY_TYPE) {
			case DCACHE_MISS_TYPE:
				err = -ENOENT;
				break;
			case DCACHE_SYMLINK_TYPE:
				if (!(nd->flags & LOOKUP_FOLLOW)) {
					err = 0;
					break;
				}
#ifdef CONFIG_DCACHE_FAST_SYMLINK
				if (unlikely(!(d_flags & DCACHE_SYMLINK_FOLLOWED)))
					break;

				nd->fast.signature = fdentry->d_link_signature;
				if (read_seqcount_retry(&fdentry->d_seq, seq)) {
					cpu_relax();
					goto seqretry;
				}
				goto rewalk;
#endif
				break;
			case DCACHE_FILE_TYPE:
				if (flags & LOOKUP_DIRECTORY) {
					err = -ENOTDIR;
					break;
				}
			default:
				err = 0;
				break;
		}

		break;
	}
	TIME_END(loop);

	if (unlikely(err == -EAGAIN))
		d_debug(E, "lookup miss: %s%s [%d:%s]\n",
			name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
			current->pid, current->comm);

	if (unlikely(err == -ENOENT))
		d_debug(I, "lookup hit but negative: %s%s => %p [%d:%s]\n",
			name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
			path.dentry, current->pid, current->comm);

	if (unlikely(err == -ENOTDIR))
		d_debug(I, "lookup hit but not a dir: %s%s => %p [%d:%s]\n",
			name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
			path.dentry, current->pid, current->comm);

	if (unlikely(err == -EACCES))
		d_debug(I, "lookup hit but access denied: %s%s => %p [%d:%s]\n",
			name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
			path.dentry, current->pid, current->comm);

	if (unlikely(err)) {
		if (err == -EAGAIN)
			INC_STAT(miss);
		else
			INC_STAT(hit);
		goto out;
	}

done:
	TIME_START(fini);
	INC_STAT(hit);
	if (*string) {
		d_debug(I, "lookup hit: %s%s => %p [%d:%s]\n",
			name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
			nd->path.dentry, current->pid, current->comm);
		retries++;
		goto rescan;
	}

	/* this will advance dentry lock refcount */
	if (!lockref_get_not_dead(&path.dentry->d_lockref))
		goto slowpath;

	mntget(path.mnt);
	nd->flags &= ~LOOKUP_RCU;
	if (path.mnt != nd->path.mnt)
		nd->flags |= LOOKUP_JUMPED;
	nd->path = path;
	BUG_ON(!nd->inode);

	d_debug(I, "lookup hit: %s%s => %p [%d:%s]\n",
		name, (flags & LOOKUP_PARENT) ? " (parent)" : "",
		path.dentry, current->pid, current->comm);

#ifdef CONFIG_DCACHE_FAST_DUMMY
	path_put(&nd->path);
	TIME_END(fini);
out:
	err = -EAGAIN;
#else
	TIME_END(fini);
out:
#endif
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	rcu_read_unlock();
out_unlocked:
	TIME_END(total);
	if (!err)
		d_profile("lookup %s [%d:%s]\n"
			  "    walk    total   init    scan    loop"
			  "    cmp     perm    barrier fini    last\n"
			  "    %7d %7llu %7llu %7llu %7llu %7llu %7llu %7llu %7llu %7llu\n",
			  name, current->pid, current->comm, walk_count,
			  TIME_VALUE(total), TIME_VALUE(init), TIME_VALUE(scan),
			  TIME_VALUE(loop),  TIME_VALUE(cmp),  TIME_VALUE(perm),
			  TIME_VALUE(barrier), TIME_VALUE(fini), TIME_VALUE(follow));
	return err;
slowpath:
	err = -EAGAIN;
	goto out;
}

int do_open_fast(struct nameidata *nd,
		 struct file *file, const struct open_flags *op,
		 int *opened, struct filename *name)
{
	bool will_truncate = (op->open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int error;

	d_debug(I, "open: %s%s => %p [%d:%s]\n", name->name,
		(nd->flags & LOOKUP_PARENT) ? " (parent)" : "",
		nd->path.dentry, current->pid, current->comm);

	error = -ENOENT;
	if (!nd->inode || d_is_negative(nd->path.dentry))
		goto out;
	audit_inode(name, nd->path.dentry, 0);
	error = -EISDIR;
	if ((op->open_flag & O_CREAT) &&
	    (d_is_directory(nd->path.dentry) || d_is_autodir(nd->path.dentry)))
		goto out;
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_is_directory(nd->path.dentry))
		goto out;
	if (!S_ISREG(nd->inode->i_mode))
		will_truncate = false;

	if (will_truncate) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto out;
		got_write = true;
	}
	
	error = may_open(&nd->path, op->acc_mode, op->open_flag);
	if (error)
		goto out;

	file->f_path.mnt = nd->path.mnt;
	error = finish_open(file, nd->path.dentry, NULL, opened);
	if (error) {
		if (error == -EOPENSTALE)
			error = -EAGAIN;
		goto out;
	}

	error = open_check_o_direct(file);
	if (error) {
		fput(file);
		goto out;
	}
	error = ima_file_check(file, op->acc_mode);
	if (error) {
		fput(file);
		goto out;
	}

	if (will_truncate) {
		error = handle_truncate(file);
		if (error) {
			fput(file);
			goto out;
		}
	}
out:
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	path_put(&nd->path);
	return error;
}

#ifdef CONFIG_DCACHE_FORCE_CANONICAL
int consume_path(struct nameidata *nd, const char **nameptr)
{
	const unsigned char *name = (const unsigned char *) *nameptr;
	unsigned depth = 0;
	int err = 0;

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
			if (!c) /* just skip the last component */
				break;
			depth++;
		} else if (type == LAST_DOTDOT) {
			if (!depth) {
				if (!c && (nd->flags & LOOKUP_PARENT))
					goto cant_dotdot;

				if (nd->flags & LOOKUP_RCU) {
					if (follow_dotdot_rcu(nd))
						return -EAGAIN;
				} else {
					follow_dotdot(nd);
				}

cant_dotdot:
				err = 1;
				nd->last = this;
				nd->last.hash =
					full_name_hash(this.name, this.len);
				nd->last_type = type;
				*nameptr = name;
				break;
			}
			depth--;
		}

		if (!c)
			return 0;
	}

	return err;
}
#endif /* CONFIG_DCACHE_FORCE_CANONICAL */

int follow_negative(struct nameidata *nd, const char **nameptr)
{
	int err = -ENOENT;

#ifdef CONFIG_DCACHE_FAST_DEEP_NEGATIVE
	err = alloc_deep_dentries(nd, nameptr, DEEP_NEGATIVE);
#elif defined(CONFIG_DCACHE_FORCE_CANONICAL)
	err = consume_path(nd, nameptr);
#endif

	if (likely(!err))
		return -ENOENT;
	else if (unlikely(err == 1))
		return 0;
	else
		return err;
}

int follow_notdir(struct nameidata *nd, const char **nameptr)
{
	int err = -ENOTDIR;

#ifdef CONFIG_DCACHE_FAST_DEEP_NOTDIR
	err = alloc_deep_dentries(nd, nameptr, DEEP_NOTDIR);
#elif defined(CONFIG_DCACHE_FORCE_CANONICAL)
	err = consume_path(nd, nameptr);
#endif

	if (likely(!err))
		return -ENOTDIR;
	else if (unlikely(err == 1))
		return 0;
	else
		return err;
}

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
#include "../mount.h"
#include "internal.h"

__cacheline_aligned_in_smp seqcount_t invalidate_seq;

static DEFINE_SPINLOCK(invalidator_lock);
static u64 invalidator_counter = 0;

void start_invalidate_fast(void)
{
	spin_lock(&invalidator_lock);
	if (!invalidator_counter) {
		write_seqcount_begin_nested(&invalidate_seq, DENTRY_D_LOCK_NESTED);
		invalidator_counter++;
		spin_unlock(&invalidator_lock);
		seqcount_release(&invalidate_seq.dep_map, 1, _RET_IP_);
		seqcount_acquire(&invalidate_seq.dep_map, 0, 1, _RET_IP_);
		return;
	}
	invalidator_counter++;
	spin_unlock(&invalidator_lock);
}

void end_invalidate_fast(void)
{
	spin_lock_nested(&invalidator_lock, DENTRY_D_LOCK_NESTED);
	invalidator_counter--;
	if (!invalidator_counter) {
		write_seqcount_end(&invalidate_seq);
		spin_release(&invalidator_lock.dep_map, 1, _RET_IP_);
		spin_acquire(&invalidator_lock.dep_map, 0, 1, _RET_IP_);
	}
	spin_unlock(&invalidator_lock);
}

struct hlist_bl_head dentry_fast_hashtable[DCACHE_FAST_HT_SIZE] __read_mostly;

void d_init_fast(struct fast_dentry *fdentry)
{
	seqcount_init(&fdentry->d_seq);
	fdentry->d_prefix = 0;
	fdentry->d_prefix_seq = PREFIX_SEQ_INVALID;
	INIT_HLIST_BL_NODE(&fdentry->d_hash);
	signature_init(&fdentry->d_signature);
	fdentry->d_mount = NULL;
#if defined(CONFIG_DCACHE_CRED_UID) || defined(CONFIG_DCACHE_CRED_ID)
	memset(fdentry->d_pcc, 0, sizeof(fdentry->d_pcc));
#endif
#ifdef CONFIG_DCACHE_FAST_SYMLINK
	signature_init(&fdentry->d_link_signature);
#endif
#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	INIT_LIST_HEAD(&fdentry->d_deep);
#endif
}

#ifdef CONFIG_USE_DEFAULT_SIGNATURE_SCHEME

#define SIGNATURE_BASE		7
unsigned long signature_factors[256] __read_mostly;

static void name_signature(path_signature_t *, const unsigned char *,
			   unsigned int);

void partial_signature(path_signature_t *signature, const unsigned char *name,
		       unsigned int len)
{
	path_signature_t s = SIGNATURE_INIT;
	register u64 factor;
	name_signature(&s, name, len);
	factor = signature_factors[signature->state + 1];
	signature->state++;
	signature->r[0] += s.r[0] * factor;
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	signature->r[1] += s.r[1] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	signature->r[2] += s.r[2] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	signature->r[3] += s.r[3] * factor;
#endif
}

void reverse_signature(path_signature_t *signature, const unsigned char *name,
		       unsigned int len)
{
	if (signature->state <= 1) {
		signature_init(signature);
	} else {
		register u64 factor = signature_factors[signature->state];
		path_signature_t s = SIGNATURE_INIT;
		name_signature(&s, name, len);
		signature->state--;
		signature->r[0] -= s.r[0] * factor;
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
		signature->r[1] -= s.r[1] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
		signature->r[2] -= s.r[2] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
		signature->r[3] -= s.r[3] * factor;
#endif
	}
}

void combine_signature(path_signature_t *signature, const path_signature_t *relative)
{
	register u64 factor = signature_factors[signature->state];
	signature->state += relative->state;
	signature->r[0]  += relative->r[0] * factor;
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	signature->r[1]  += relative->r[1] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	signature->r[2]  += relative->r[2] * factor;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	signature->r[3]  += relative->r[3] * factor;
#endif
}

#endif /* DEFAULT_USE_DEFAULT_SIGNATURE_SCHEME */


#ifdef CONFIG_PATH_SIGNATURE_SIMPLE
void
name_signature(path_signature_t *signature, const unsigned char *name,
	       unsigned int len)
{
	signature->r[0] = full_name_hash(name, len);
}
#endif

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_OLD
#include "jelkins.h"
void
name_signature(path_signature_t *signature, const unsigned char *name,
	       unsigned int len)
{
	signature->r[0] = jelkins_old_hash(name, len, 0);
}
#endif

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_LOOKUP3
#include "jelkins.h"
void
name_signature(path_signature_t *signature, const unsigned char *name,
	       unsigned int len)
{
	signature_init(signature);
	jelkins_lookup3_hash64(name, len, &((u32 *) signature->r)[0],
			       &((u32 *)signature->r)[1]);
}
#endif

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_SPOOKY
#include "jelkins.h"
void
name_signature(path_signature_t *signature, const unsigned char *name,
	       unsigned int len)
{
	signature_init(signature);
	jelkins_spooky_hash128(name, len, &signature->r[0], &signature->r[1]);
}
#endif

#ifdef CONFIG_USE_MHASH
#include"mhash.h"

void partial_signature(path_signature_t *signature, const unsigned char *name,
		       unsigned int len)
{
	BUG_ON(name[0] == '/');
	BUG_ON(name[0] == '.' && len == 1);
	BUG_ON(name[0] == '.' && name[1] == '.' && len == 2);

	signature->state =
		mhash_hash(name, len, signature->r, signature->state);
}

void reverse_signature(path_signature_t *signature, const unsigned char *name,
		       unsigned int len)
{
	u64 o_state = signature->state;
	u64 r_state = o_state - ((len + (MHASH_L/8) - 1) / (MHASH_L/8));
	u64 n_state;

	if (!o_state)
		return;

	if (!r_state)
		signature_init(signature);

	BUG_ON(r_state >= o_state);
	n_state = mhash_hash(name, len, signature->r, r_state);
	BUG_ON(n_state != o_state);
	signature->state = r_state;
}

void combine_signature(path_signature_t *signature, const path_signature_t *relative)
{
	signature->r[0]  ^= relative->r[0];
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	signature->r[1]  ^= relative->r[1];
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	signature->r[2]  ^= relative->r[2];
#endif
	signature->state += relative->state;
}

#endif /* USE_MHASH */

#ifdef CONFIG_PATH_SIGNATURE_AES_KHASH
#include "aes-khash.h"
void
name_signature(path_signature_t *signature, const unsigned char *name,
	       unsigned int len)
{
	signature_init(signature);
	aesni_khash_hash(name, len, (u8 *) signature->r);
}
#endif

int d_alloc_fast(struct fast_dentry *fdentry, struct fast_dentry *fparent,
		 const struct qstr *name)
{
	if (name->len > 1 || name->name[0] != '/') {
		if (fparent)
			fdentry->d_signature = fparent->d_signature;

		partial_signature(&fdentry->d_signature, name->name,
				  name->len);
	}

	return 0;
}

void d_free_fast(struct fast_dentry *fdentry)
{
	/* do nothing */
}

void __d_shrink_fast(struct fast_dentry *fdentry)
{
	if (!d_unhashed_fast(fdentry)) {
		struct hlist_bl_head *b = d_hash_fast(&fdentry->d_signature);
		hlist_bl_lock(b);
		__hlist_bl_del(&fdentry->d_hash);
		fdentry->d_hash.pprev = NULL;
		hlist_bl_unlock(b);
	}

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	if (!(fdentry->d_flags & DCACHE_DEEP_DENTRY))
		__d_shrink_deep(fdentry);
#endif
}

void d_shrink_fast(struct fast_dentry *fdentry)
{
	struct dentry *dentry = real_dentry(fdentry);
	spin_lock(&dentry->d_lock);
	__d_shrink_fast(fdentry);
	spin_unlock(&dentry->d_lock);
}

void __d_rehash_fast(struct fast_dentry *fdentry, struct hlist_bl_head *b)
{
	BUG_ON(!d_unhashed_fast(fdentry));
	hlist_bl_lock(b);
	fdentry->d_flags |= DCACHE_RCUACCESS;
	hlist_bl_add_head_rcu(&fdentry->d_hash, b);
	hlist_bl_unlock(b);
}

void _d_rehash_fast(struct fast_dentry *fdentry)
{
	__d_rehash_fast(fdentry, d_hash_fast(&fdentry->d_signature));
}

void d_rehash_fast(struct fast_dentry *fdentry)
{
	struct dentry *dentry = real_dentry(fdentry);
	spin_lock(&dentry->d_lock);
	_d_rehash_fast(fdentry);
	spin_unlock(&dentry->d_lock);
}

enum d_walk_nested_ret {
	D_WALK_NESTED_CONTINUE,
	D_WALK_NESTED_QUIT,
	D_WALK_NESTED_NORETRY,
	D_WALK_NESTED_SKIP,
	D_WALK_NESTED_RETRY,
};

enum d_walk_nested_ret
d_walk_in_nest(struct dentry *parent, void *data,
	       enum d_walk_nested_ret (*enter)(void *, struct dentry *, unsigned),
	       void (*finish)(void *), unsigned seq)
{
	struct dentry *this_parent;
	struct list_head *next;
	enum d_walk_nested_ret ret;
	bool retry = true;

	this_parent = parent;
	spin_lock(&this_parent->d_lock);

	ret = enter(data, this_parent, seq);
	switch (ret) {
	case D_WALK_NESTED_CONTINUE:
		break;
	case D_WALK_NESTED_RETRY:
	case D_WALK_NESTED_QUIT:
	case D_WALK_SKIP:
		goto out_unlock;
	case D_WALK_NESTED_NORETRY:
		retry = false;
		break;
	}
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;

		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);

		ret = enter(data, dentry, seq);
		switch (ret) {
		case D_WALK_NESTED_CONTINUE:
			break;
		case D_WALK_NESTED_RETRY:
		case D_WALK_NESTED_QUIT:
			spin_unlock(&dentry->d_lock);
			goto out_unlock;
		case D_WALK_NESTED_NORETRY:
			retry = false;
			break;
		case D_WALK_NESTED_SKIP:
			spin_unlock(&dentry->d_lock);
			continue;
		}

		if (!list_empty(&dentry->d_subdirs)) {
			spin_unlock(&this_parent->d_lock);
			spin_release(&dentry->d_lock.dep_map, 1, _RET_IP_);
			this_parent = dentry;
			spin_acquire(&this_parent->d_lock.dep_map, 0, 1, _RET_IP_);
			goto repeat;
		}
		spin_unlock(&dentry->d_lock);
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		struct dentry *child = this_parent;
		this_parent = child->d_parent;

		rcu_read_lock();
		spin_unlock(&child->d_lock);
		spin_lock(&this_parent->d_lock);

		/*
		 * might go back up the wrong parent if we have had a rename
		 * or deletion
		 */
		if (this_parent != child->d_parent ||
			 (child->d_flags & DCACHE_DENTRY_KILLED) ||
			 need_seqretry(&rename_lock, seq)) {
			rcu_read_unlock();
			ret = D_WALK_NESTED_RETRY;
			goto out_unlock;
		}
		rcu_read_unlock();
		next = child->d_u.d_child.next;
		goto resume;
	}
	if (need_seqretry(&rename_lock, seq)) {
		ret = D_WALK_NESTED_RETRY;
		goto out_unlock;
	}
	if (finish)
		finish(data);

out_unlock:
	spin_unlock(&this_parent->d_lock);
	return ret;
}

void d_walk_nested(struct dentry *parent, void *data,
		   enum d_walk_nested_ret (*enter)(void *, struct dentry *, unsigned),
		   void (*finish)(void *))
{
	unsigned seq = 0;
	enum d_walk_nested_ret ret;

again:
	read_seqbegin_or_lock(&rename_lock, &seq);

	ret = d_walk_in_nest(parent, data, enter, finish, seq);
	if (ret == D_WALK_NESTED_RETRY) {
		seq = 1;
		goto again;
	}

	done_seqretry(&rename_lock, seq);
}

struct d_invalidate_walk_data {
	bool			namespace_locked;
	struct dentry *		root;
	struct vfsmount *	mount;
};

static enum d_walk_nested_ret
d_invalidate_fast_walk(void *data, struct dentry *dentry, unsigned seq);

static enum d_walk_nested_ret
d_invalidate_mount(struct vfsmount *mnt, struct dentry *dentry, unsigned seq,
		   bool namespace_locked)
{
	struct dentry *root = mnt->mnt_root;
	enum d_walk_nested_ret ret;

	if (root != dentry) {
		struct d_invalidate_walk_data data;
		data.namespace_locked = namespace_locked;
		data.root = NULL;
		data.mount = mnt;

		/* now make the walk on the new root */
		ret = d_walk_in_nest(root, &data, d_invalidate_fast_walk,
				     NULL, seq);
	}

	return D_WALK_NESTED_CONTINUE;
}

static enum d_walk_nested_ret
d_invalidate_fast_walk(void *data, struct dentry *dentry, unsigned seq)
{
	/*XXX: this part is causing deadlock */
#if 0
	struct d_invalidate_walk_data *old = data;
	enum d_walk_nested_ret ret;

	if (dentry != old->root && d_mountpoint(dentry)) {
		struct vfsmount *parent_mnt = old->mount;
		if (parent_mnt) {
			struct mount *mnt;
			rcu_read_lock();
			mnt = __lookup_mnt(parent_mnt, dentry);
			if (!mnt) {
				rcu_read_unlock();
				goto do_invalidate;
			}
			rcu_read_unlock();

			ret = d_invalidate_mount(&mnt->mnt, dentry, seq,
						 old->namespace_locked);

			if (ret == D_WALK_NESTED_CONTINUE)
				goto do_invalidate;
		} else {
			struct mountpoint *mp = NULL;
			struct mount *mnt;

			if (!old->namespace_locked)
				namespace_lock();

			mp = lookup_mountpoint(dentry);
			if (!mp) {
				if (!old->namespace_locked)
					namespace_unlock();
				goto do_invalidate;
			}

			hlist_for_each_entry(mnt, &mp->m_list, mnt_mp_list) {
				ret = d_invalidate_mount(&mnt->mnt, dentry,
							 seq, true);

				switch(ret) {
					case D_WALK_NESTED_CONTINUE:
						goto do_invalidate;
					case D_WALK_NESTED_SKIP:
						continue;
					case D_WALK_NESTED_RETRY:
					case D_WALK_NESTED_QUIT:
					case D_WALK_NESTED_NORETRY:
						put_mountpoint(mp);
						if (!old->namespace_locked)
							namespace_unlock();
						return ret;
				}
			}

			put_mountpoint(mp);
			if (!old->namespace_locked)
				namespace_unlock();
		}
	}

do_invalidate:
#endif

	d_debug(D, "invalidate " DENTRY_NAME_FMT "\n",
		DENTRY_NAME_PRINTK(dentry));

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	__d_shrink_deep(&dentry->d_fast);
#endif

	write_seqcount_barrier(&dentry->d_fast.d_seq);
	dentry->d_fast.d_prefix_seq = PREFIX_SEQ_INVALID;
	return D_WALK_CONTINUE;
}

void __d_invalidate_fast(struct vfsmount * mount, struct dentry *dentry)
{
	struct d_invalidate_walk_data data;
	data.namespace_locked = false;
	data.root = dentry;
	data.mount = mount;
	d_walk_nested(dentry, &data, d_invalidate_fast_walk, NULL);
}

void __init fast_dcache_init(void)
{
	unsigned int loop;
	unsigned int nbuckets = 1U << CONFIG_DCACHE_FAST_HASHTABLE_ORDER;

	printk(KERN_INFO "fast dentry size = %ld, offset = %ld\n",
	       sizeof(struct fast_dentry), offsetof(struct dentry, d_fast));

	for (loop = 0; loop < (1U << CONFIG_DCACHE_FAST_HASHTABLE_ORDER); loop++)
		INIT_HLIST_BL_HEAD(dentry_fast_hashtable + loop);

	printk(KERN_INFO "DLHT initialized (%d buckets)\n", nbuckets);

#ifdef CONFIG_USE_DEFAULT_SIGNATURE_SCHEME
	signature_factors[0] = 1;
	for (loop = 1; loop < 256; loop++)
		signature_factors[loop] = signature_factors[loop-1] *
					  SIGNATURE_BASE;
#endif

#ifdef CONFIG_USE_MHASH
	mhash_init();
#endif
#ifdef CONFIG_PATH_SIGNATURE_AES_KHASH
	aesni_khash_init();
#endif

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	deep_dentry_init();
#endif
}

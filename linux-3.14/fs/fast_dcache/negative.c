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
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/mount.h>
#include <asm/uaccess.h>

#include "../internal.h"
#include "internal.h"

/* this function should not be blocking */
void __d_create_negative(struct dentry *dentry)
{
	struct dentry *negative, *parent = dentry->d_parent;
	char *dname;

	if (unlikely(!dentry->d_op || (dentry->d_flags & DCACHE_OP_REVALIDATE)))
		return;

	d_debug(I, "negative: %p (%s) parent: %p (%s)\n",
		dentry, dentry->d_name.name, parent, parent->d_name.name);

	negative = kmem_cache_alloc(dentry_cache, GFP_ATOMIC);
	if (!negative)
		return;

	negative->d_iname[DNAME_INLINE_LEN-1] = 0;
	if (dentry->d_name.len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(dentry->d_name.len + 1, GFP_ATOMIC);
		if (!dname) {
			kmem_cache_free(dentry_cache, negative);
			return;
		}
	} else {
		dname = negative->d_iname;
	}

	negative->d_name.len = dentry->d_name.len;
	negative->d_name.hash = dentry->d_name.hash;
	memcpy(dname, dentry->d_name.name, dentry->d_name.len);
	dname[dentry->d_name.len] = 0;

	smp_wmb();
	negative->d_name.name = dname;

	negative->d_lockref.count = 0;
	negative->d_flags = DCACHE_MISS_TYPE;
	spin_lock_init(&negative->d_lock);
	seqcount_init(&negative->d_seq);
	negative->d_inode = NULL;
	negative->d_parent = parent;
	negative->d_sb = parent->d_sb;
	negative->d_op = NULL;
	negative->d_fsdata = NULL;
	INIT_HLIST_BL_NODE(&negative->d_hash);
	INIT_LIST_HEAD(&negative->d_lru);
	INIT_LIST_HEAD(&negative->d_subdirs);
	INIT_HLIST_NODE(&negative->d_alias);
	INIT_LIST_HEAD(&negative->d_u.d_child);
	d_set_d_op(negative, negative->d_sb->s_d_op);

#ifdef CONFIG_DCACHE_FAST
	d_init_fast(&negative->d_fast);
	negative->d_fast.d_prefix = dentry->d_fast.d_prefix;
	negative->d_fast.d_prefix_seq = dentry->d_fast.d_prefix_seq;
	negative->d_fast.d_signature = dentry->d_fast.d_signature;
	negative->d_fast.d_mount = dentry->d_fast.d_mount;
#endif
#ifdef CONFIG_DCACHE_COMPLETENESS
	d_init_complete(&negative->d_complete);
#endif

	parent->d_lockref.count++;
	list_add(&negative->d_u.d_child, &parent->d_subdirs);

	spin_lock_nested(&negative->d_lock, DENTRY_D_LOCK_NESTED);
	_d_rehash(negative);
#ifdef CONFIG_DCACHE_FAST
	_d_rehash_fast(&negative->d_fast);
#endif
	negative->d_flags |= DCACHE_REFERENCED;
	dentry_lru_add(negative);
	spin_unlock(&negative->d_lock);
}

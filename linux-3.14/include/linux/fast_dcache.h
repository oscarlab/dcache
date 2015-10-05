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

#ifndef __LINUX_FAST_DCACHE_H
#define __LINUX_FAST_DCACHE_H

#include <uapi/linux/limits.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/lockref.h>
#include <linux/path.h>
#include <linux/random.h>

struct qstr;
struct dir_context;
struct lockref;

#if defined(CONFIG_DCACHE_FAST) || defined(CONFIG_DCACHE_FAST_STRUCTURE_ONLY)

#if defined(CONFIG_DCACHE_CRED_UID) || defined(CONFIG_DCACHE_CRED_ID)

#ifdef CONFIG_DCACHE_CRED_ID
struct dentry_info {
	__u32		cid;
};
#define CID_INVALID		0x80000000UL
#define CID_MAX_DEFAULT		0x7fffffffUL

#define DENTRY_INFO_DEFAULT	{ .cid = CID_INVALID }

static inline void init_dentry_info(struct dentry_info *dentry_info)
{
	dentry_info->cid = CID_INVALID;
}

#define get_dentry_info(d) do {} while (0)
#define put_dentry_info(d) do {} while (0)

u32 new_cid(void);

static inline void commit_dentry_info(struct dentry_info *dentry_info)
{
	if (dentry_info->cid == CID_INVALID)
		dentry_info->cid = new_cid();
}
#else
struct dentry_info {
	__u32		reserved;
};

#define UID_ROOT		0x7fffffffULL

#define DENTRY_INFO_DEFAULT	{}

#define init_dentry_info(d) do {} while (0)
#define get_dentry_info(d) do {} while (0)
#define put_dentry_info(d) do {} while (0)
#define commit_dentry_info(d) do {} while (0)

#endif /* CONFIG_DCACHE_CRED_ID */

/*
 * each prefix check cache entry is 8 bytes.
 */
struct dentry_pcc {
	u32 recently:1;
	u32 cred:31;
	unsigned seq;
};
#endif /* CONFIG_DCACHE_CRED_UID || CONFIG_DCACHE_CRED_ID */

typedef struct {
	u64 r[CONFIG_PATH_SIGNATURE_SIZE / 64];
	u32 state;
} path_signature_t __attribute__((aligned(32)));

/*
 * except prefix check cache (if used), a fast dentry is strictly aligned to
 * L1 cache line.
 */
struct fast_dentry {
	unsigned int		d_flags;		/* 04 bytes */
							/* shares memory space
							 * with d_flags in
							 * struct dentry */
	seqcount_t		d_seq;			/* 04 bytes */
	u32			d_prefix;		/* 04 bytes */
	unsigned		d_prefix_seq;		/* 04 bytes */
	struct hlist_bl_node	d_hash;			/* 16 bytes */
	path_signature_t	d_signature;		/* 32 + 04 bytes */

#if defined(CONFIG_DCACHE_CRED_UID) || defined(CONFIG_DCACHE_CRED_ID)
	struct dentry_pcc	d_pcc[CONFIG_DCACHE_PCC_SIZE];
#endif

	struct vfsmount *	d_mount;		/* 08 bytes */

#ifdef CONFIG_DCACHE_FAST_SYMLINK
	path_signature_t	d_link_signature;	/* 32 + 04 bytes */
#endif

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
	struct list_head	d_deep;			/* 16 bytes */
#endif
} ____cacheline_aligned;

#endif /* DCACHE_FAST || DCACHE_FAST_STRUCTURE_ONLY */

#ifdef CONFIG_DCACHE_FAST

#define PREFIX_SEQ_INVALID	(1)

#ifdef CONFIG_DCACHE_CRED_PCC

struct cred_pcc_entry {
	union {
		struct {
			u32 recently:1;
			u32 dentry:31;
			u32 seq;
		};
		u64 raw;
	};
};

#define PCC_RECENTLY_MASK	1ULL

struct cred_pcc {
	atomic_t	usage;
	struct rcu_head rcu;
	struct cred_pcc_entry entries[] ____cacheline_aligned;
};

struct dentry_info {
	struct list_head chained;
	struct cred_pcc *pcc;
};

#define DENTRY_INFO_DEFAULT	{ .pcc = NULL }

extern void __put_cred_pcc(struct cred_pcc *pcc);
extern struct cred_pcc *__alloc_cred_pcc(void);

static inline void get_dentry_info(struct dentry_info *dentry_info)
{
	if (dentry_info->pcc)
		atomic_inc(&dentry_info->pcc->usage);
}

static inline void put_dentry_info(struct dentry_info *dentry_info)
{
	if (dentry_info->pcc &&
	    atomic_dec_and_test(&dentry_info->pcc->usage))
		__put_cred_pcc(dentry_info->pcc);
}

static inline void init_dentry_info(struct dentry_info *dentry_info)
{
	if (dentry_info->pcc) {
		put_dentry_info(dentry_info);
		dentry_info->pcc = NULL;
	}
}

static inline void commit_dentry_info(struct dentry_info *dentry_info)
{
	if (!dentry_info->pcc)
		dentry_info->pcc = __alloc_cred_pcc();
}

#endif /* CONFIG_DCACHE_CRED_PCC */

struct fast_nameidata {
	unsigned		invalidate_seq;
	struct dentry_info	dentry_info;
	u32			prefix;
	unsigned		prefix_seq;
	path_signature_t	signature;
#ifdef CONFIG_DCACHE_FAST_SYMLINK
	unsigned		link_depth, nested_link_depth;
	struct link_nameidata {
		u32			prefix;
		unsigned		prefix_seq;
		struct path		link;
		path_signature_t	signature;
	} links[MAX_NESTED_LINKS+1];
#endif
};

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES

#define DCACHE_DEEP_DENTRY	0x30000000

#define DEEP_SYMLINK		0x10000000
#define DEEP_NEGATIVE		0x20000000
#define DEEP_NOTDIR		0x30000000

#define DCACHE_SYMLINK_FOLLOWED	0x40000000

struct deep_dentry {
	struct fast_dentry	d_fast, *d_root;
	struct lockref		d_lockref;
	struct rcu_head		d_rcu;
};

#endif /* CONFIG_DCACHE_FAST_DEEP_DENTRIES */

#define LOOKUP_FAST			0x10000
#define LOOKUP_CACHE_FAST		0x20000

#endif /* CONFIG_DCACHE_FAST */

#ifdef CONFIG_DCACHE_COMPLETENESS

struct dir_complete {
	union {
		seqcount_t d_dir_gen;
		u64 d_ino;
	};
};

#define DENTRY_NEED_LOOKUP	0x80000000

#define DCACHE_OTHER_TYPE	0x07000000
#define DCACHE_REGULAR_TYPE	0x01000000
#define DCACHE_FIFO_TYPE	0x02000000
#define DCACHE_CHAR_TYPE	0x03000000
#define DCACHE_BLOCK_TYPE	0x04000000
#define DCACHE_SOCK_TYPE	0x05000000
#define DCACHE_UNKNOWN_TYPE	0x06000000

#define DCACHE_DIR_COMPLETE	0x08000000	/* dentry with the all entries
						   in the directory listed as
						   children of it. */

#define d_need_lookup(dentry) (!d_is_negative(dentry) && !(dentry)->d_inode)


#endif /* CONFIG_DCACHE_COMPLETENESS */

#endif /* __LINUX_FAST_DCACHE_H */

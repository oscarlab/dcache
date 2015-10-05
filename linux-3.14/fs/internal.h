/* fs/ internal definitions
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

struct super_block;
struct file_system_type;
struct linux_binprm;
struct path;
struct mount;

/*
 * block_dev.c
 */
#ifdef CONFIG_BLOCK
extern void __init bdev_cache_init(void);

extern int __sync_blockdev(struct block_device *bdev, int wait);

#else
static inline void bdev_cache_init(void)
{
}

static inline int __sync_blockdev(struct block_device *bdev, int wait)
{
	return 0;
}
#endif

/*
 * char_dev.c
 */
extern void __init chrdev_init(void);

/*
 * namei.c
 */
extern int __inode_permission(struct inode *, int);
extern int user_path_mountpoint_at(int, const char __user *, unsigned int, struct path *);
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct path *);
extern unsigned long hash_name(const char *name, unsigned int *hashp);
extern int follow_dotdot_rcu(struct nameidata *nd);
extern void follow_dotdot(struct nameidata *nd);
extern int may_open(struct path *path, int acc_mode, int flag);
extern int handle_truncate(struct file *filp);
extern int complete_walk(struct nameidata *nd);

/*
 * namespace.c
 */
extern int copy_mount_options(const void __user *, unsigned long *);
extern int copy_mount_string(const void __user *, char **);

extern void namespace_lock(void);
extern void namespace_unlock(void);

extern struct vfsmount *lookup_mnt(struct path *);
extern int finish_automount(struct vfsmount *, struct path *);
extern struct mountpoint *lookup_mountpoint(struct dentry *dentry);
extern void put_mountpoint(struct mountpoint *);
extern int sb_prepare_remount_readonly(struct super_block *);

extern void __init mnt_init(void);

extern int __mnt_want_write(struct vfsmount *);
extern int __mnt_want_write_file(struct file *);
extern void __mnt_drop_write(struct vfsmount *);
extern void __mnt_drop_write_file(struct file *);

/*
 * fs_struct.c
 */
extern void chroot_fs_refs(const struct path *, const struct path *);

/*
 * file_table.c
 */
extern struct file *get_empty_filp(void);

/*
 * super.c
 */
extern int do_remount_sb(struct super_block *, int, void *, int);
extern bool grab_super_passive(struct super_block *sb);
extern struct dentry *mount_fs(struct file_system_type *,
			       int, const char *, void *);
extern struct super_block *user_get_super(dev_t);

/*
 * open.c
 */
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};
extern struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op);
extern struct file *do_file_open_root(struct dentry *, struct vfsmount *,
		const char *, const struct open_flags *);

extern long do_handle_open(int mountdirfd,
			   struct file_handle __user *ufh, int open_flag);
extern int open_check_o_direct(struct file *f);

/*
 * inode.c
 */
extern spinlock_t inode_sb_list_lock;
extern long prune_icache_sb(struct super_block *sb, unsigned long nr_to_scan,
			    int nid);
extern void inode_add_lru(struct inode *inode);

/*
 * fs-writeback.c
 */
extern void inode_wb_list_del(struct inode *inode);

extern long get_nr_dirty_inodes(void);
extern void evict_inodes(struct super_block *);
extern int invalidate_inodes(struct super_block *, bool);

/*
 * dcache.c
 */
extern struct kmem_cache *dentry_cache;
extern struct dentry *__d_alloc(struct super_block *, const struct qstr *);
extern void _d_rehash(struct dentry *);
extern void dentry_lru_add(struct dentry *);
extern int d_set_mounted(struct dentry *dentry);
extern long prune_dcache_sb(struct super_block *sb, unsigned long nr_to_scan,
			    int nid);

/**
 * enum d_walk_ret - action to talke during tree walk
 * @D_WALK_CONTINUE:	contrinue walk
 * @D_WALK_QUIT:	quit walk
 * @D_WALK_NORETRY:	quit when retry is needed
 * @D_WALK_SKIP:	skip this dentry and its children
 */
enum d_walk_ret {
	D_WALK_CONTINUE,
	D_WALK_QUIT,
	D_WALK_NORETRY,
	D_WALK_SKIP,
};

/**
 * d_walk - walk the dentry tree
 * @parent:	start of walk
 * @data:	data passed to @enter() and @finish()
 * @enter:	callback when first entering the dentry
 * @finish:	callback when successfully finished the walk
 *
 * The @enter() and @finish() callbacks are called with d_lock held.
 */
extern void d_walk(struct dentry *parent, void *data,
		   enum d_walk_ret (*enter)(void *, struct dentry *),
		   void (*finish)(void *));

/*
 * read_write.c
 */
extern ssize_t __kernel_write(struct file *, const char *, size_t, loff_t *);
extern int rw_verify_area(int, struct file *, const loff_t *, size_t);

/*
 * splice.c
 */
extern long do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
		loff_t *opos, size_t len, unsigned int flags);

/*
 * pipe.c
 */
extern const struct file_operations pipefifo_fops;

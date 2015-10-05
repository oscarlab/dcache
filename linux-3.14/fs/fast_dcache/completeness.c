#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/mount.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>

#include "../internal.h"
#include "internal.h"

#ifdef CONFIG_DCACHE_LOOKUP_STAT
/* Collect lookup statistics. */
struct dcache_complete_stat_t dcache_complete_stat;

static DEFINE_PER_CPU(long, entry_cached);
static DEFINE_PER_CPU(long, entry_omitted);
static DEFINE_PER_CPU(long, dir_complete);
static DEFINE_PER_CPU(long, dir_incomplete);
static DEFINE_PER_CPU(long, dir_iteratable);

int dcache_enable_complete_stat __read_mostly = 0;

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_dcache_complete_stat(ctl_table *table, int write, void __user *buffer,
			      size_t *lenp, loff_t *ppos)
{
	int i;
	struct dcache_complete_stat_t stat = { 0, 0, };
	for_each_possible_cpu(i) {
		stat.entry_cached	+= per_cpu(entry_cached,	i);
		stat.entry_omitted	+= per_cpu(entry_omitted,	i);
		stat.dir_complete	+= per_cpu(dir_complete,	i);
		stat.dir_incomplete	+= per_cpu(dir_incomplete,	i);
		stat.dir_iteratable	+= per_cpu(dir_iteratable,	i);

	}
	dcache_complete_stat = stat;
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}

int proc_dcache_enable_complete_stat(ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos)
{
	int error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (!error && write && dcache_enable_complete_stat == 2) {
		int i;
		for_each_possible_cpu(i) {
			per_cpu(entry_cached,	i) = 0;
			per_cpu(entry_omitted,	i) = 0;
			per_cpu(dir_complete,	i) = 0;
			per_cpu(dir_incomplete,	i) = 0;
			per_cpu(dir_iteratable,	i) = 0;
		}
	}
	return error;
}
#endif

#define INC_STAT(type)						\
	do {							\
		if (dcache_enable_complete_stat)		\
			this_cpu_inc(type);			\
	} while (0)
#else
#define INC_STAT(type) do {} while (0)
#endif /* DCACHE_LOOKUP_STAT */

void d_instantiate_complete(struct dentry *dentry)
{
	if (d_need_lookup(dentry) || d_is_negative(dentry))
		return;

	dentry->d_flags &= ~DCACHE_OTHER_TYPE;

	if (d_is_directory(dentry))
		seqcount_init(&dentry->d_complete.d_dir_gen);
}

static struct file_operations fast_dir_operations;

void maybe_d_alloc_for_readdir(struct file *file, const char *name, int namlen,
			       u64 ino, unsigned int d_type)
{
	struct dentry *dir, *dentry;
	struct qstr q;
	unsigned seq = file->f_dir_gen;

	if (!file || file->f_op == &fast_dir_operations)
		return;

	dir = file->f_path.dentry;

	if (!d_can_complete(dir))
		return;

	/* skip dot and dot-dot; these dentries already have inodes */
	if (namlen == 1 && name[0] == '.')
		return;
	if (namlen == 2 && name[0] == '.' && name[1] == '.')
		return;

	if (read_seqcount_retry(&dir->d_complete.d_dir_gen, seq))
		return;

	q.name = name;
	q.len = namlen;
	q.hash = full_name_hash(q.name, q.len);

	dentry = d_lookup(dir, &q);
	if (!dentry) {
		dentry = d_alloc(dir, &q);
		if (!dentry)
			return;

		INC_STAT(entry_cached);

		d_debug(I, "add from dir: " DENTRY_NAME_FMT " ino %llx type %d\n",
			DENTRY_NAME_PRINTK(dentry), ino, d_type);

		dentry->d_flags |= DENTRY_NEED_LOOKUP;
		dentry->d_complete.d_ino = ino;
		switch(d_type) {
			case DT_FIFO:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_FIFO_TYPE;
				break;
			case DT_CHR:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_CHAR_TYPE;
				break;
			case DT_DIR:
				dentry->d_flags |= DCACHE_DIRECTORY_TYPE;
				break;
			case DT_BLK:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_BLOCK_TYPE;
				break;
			case DT_REG:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_REGULAR_TYPE;
				break;
			case DT_LNK:
				dentry->d_flags |= DCACHE_SYMLINK_TYPE;
				break;
			case DT_SOCK:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_SOCK_TYPE;
				break;
			case DT_UNKNOWN:
				dentry->d_flags |= DCACHE_FILE_TYPE|DCACHE_UNKNOWN_TYPE;
				break;
		}
		d_rehash(dentry);
	}

	dput(dentry);
}

void try_mark_dir_complete(struct file *file)
{
	if (file) {
		struct dentry *dir = file->f_dentry;
		unsigned seq = file->f_dir_gen;

		if (file->f_op == &fast_dir_operations)
			return;

		if (!d_can_complete(dir))
			return;

		spin_lock(&dir->d_lock);
		if (!__read_seqcount_retry(&dir->d_complete.d_dir_gen, seq)) {
			d_debug(I, "mark dir complete: " DENTRY_NAME_FMT "\n",
				DENTRY_NAME_PRINTK(dir));
			dir->d_flags |= DCACHE_DIR_COMPLETE;
			write_seqcount_barrier(&dir->d_complete.d_dir_gen);
			INC_STAT(dir_complete);
		} else {
			INC_STAT(dir_incomplete);
		}
		spin_unlock(&dir->d_lock);
	}
}

static int
fast_filldir(struct dentry *dentry, const char *name, int namlen,
	     struct dir_context *ctx)
{
	struct inode *inode = dentry->d_inode;
	u64 ino;
	unsigned d_type = DT_UNKNOWN;

	INC_STAT(entry_omitted);

	if (inode) {
		ino = inode->i_ino;
		switch (inode->i_mode & S_IFMT) {
			case S_IFIFO:	d_type = DT_FIFO;	break;
			case S_IFCHR:	d_type = DT_CHR;	break;
			case S_IFDIR:	d_type = DT_DIR;	break;
			case S_IFBLK:	d_type = DT_BLK;	break;
			case S_IFREG:	d_type = DT_REG;	break;
			case S_IFLNK:	d_type = DT_LNK;	break;
			case S_IFSOCK:	d_type = DT_SOCK;	break;
		}
	} else {
		ino = dentry->d_complete.d_ino;
		switch (dentry->d_flags & DCACHE_ENTRY_TYPE) {
			case DCACHE_DIRECTORY_TYPE:
			case DCACHE_AUTODIR_TYPE:
				d_type = DT_DIR;
				break;
			case DCACHE_SYMLINK_TYPE:
				d_type = DT_LNK;
				break;
			case DCACHE_FILE_TYPE:
				d_type = DT_REG;
				break;
			default:
				return 0;
		}
		if (d_type == DT_REG)
			switch (dentry->d_flags & DCACHE_OTHER_TYPE) {
				case DCACHE_REGULAR_TYPE:
					break;
				case DCACHE_FIFO_TYPE:
					d_type = DT_FIFO;
					break;
				case DCACHE_CHAR_TYPE:
					d_type = DT_CHR;
					break;
				case DCACHE_BLOCK_TYPE:
					d_type = DT_BLK;
					break;
				case DCACHE_SOCK_TYPE:
					d_type = DT_SOCK;
					break;
				case DCACHE_UNKNOWN_TYPE:
					d_type = DT_UNKNOWN;
					break;
				default:
					return 0;
			}
	}

	if (!dir_emit(ctx, name, namlen, ino, d_type))
		return 1;

	return 0;
}

#define DENTRY_BUFFER_SIZE	32

static int fast_iterate(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *child = NULL;
	int flags = ACCESS_ONCE(dentry->d_flags);
	struct list_head *lh = (struct list_head *) ctx->pos;
	int ret = 0;
	struct dentry *buffer[DENTRY_BUFFER_SIZE];
	unsigned buffered, i;
	BUG_ON(!(flags & DCACHE_DIR_COMPLETE));

	if (lh == ERR_PTR(EFAULT))
		return 0;

	rcu_read_lock();

	if (lh && lh != &dentry->d_subdirs) {
		child = list_entry(lh, struct dentry, d_u.d_child);

		if (child->d_parent != dentry) {
			ret = -ESTALE;
			goto out;
		}

		dput(child);
		spin_lock(&dentry->d_lock);
		goto walk;
	}

	if (!lh) {
		/* emit dot/dotdot */
		ret = fast_filldir(dentry->d_parent, "..", 2, ctx);
		if (ret)
			goto out;

		lh = &dentry->d_subdirs;
	}

	if (lh == &dentry->d_subdirs) {
		/* after this, dentry->d_lock is unlocked */
		ret = fast_filldir(dentry, ".", 2, ctx);
		if (ret)
			goto out;

		spin_lock(&dentry->d_lock);

		if (list_empty(&dentry->d_subdirs)) {
			lh = ERR_PTR(EFAULT);
			spin_unlock(&dentry->d_lock);
			goto out;
		}

		lh = dentry->d_subdirs.next;
	} else {
		spin_lock(&dentry->d_lock);
	}

walk:
	buffered = 0;

	for (; lh != &dentry->d_subdirs; lh = lh->next) {
		child = list_entry(lh, struct dentry, d_u.d_child);

		/* negative or removed dentry */
		if (unlikely(d_unhashed(child) || d_is_negative(child)))
			continue;

		if (child->d_parent != dentry) {
			ret = -ESTALE;
			spin_unlock(&dentry->d_lock);
			goto out;
		}

		d_debug(I, "iterate dentry: " DENTRY_NAME_FMT "\n",
			DENTRY_NAME_PRINTK(child));

		if (buffered == DENTRY_BUFFER_SIZE)
			break;

		buffer[buffered++] = child;
	}

	spin_unlock(&dentry->d_lock);

	if (buffered) {
		for (i = 0 ; i < buffered ; i++) {
			child = buffer[i];

			/* after this, child->d_lock is unlocked */
			ret = fast_filldir(child, child->d_name.name, child->d_name.len,
					   ctx);
			if (ret) {
				lh = &child->d_u.d_child;
				goto end;
			}
		}

		if (buffered == DENTRY_BUFFER_SIZE) {
			spin_lock(&dentry->d_lock);
			goto walk;
		}
	}

end:
	if (lh == &dentry->d_subdirs) {
		lh = ERR_PTR(EFAULT);
	} else {
		dget(list_entry(lh, struct dentry, d_u.d_child));
	}
out:
	rcu_read_unlock();
	ctx->pos = (loff_t) lh;
	return ret;
}

static int fast_release_dir(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct list_head *lh = (struct list_head *) file->f_pos;

	if (lh == ERR_PTR(EFAULT))
		return 0;
	if (!lh)
		return 0;
	if (lh == &dentry->d_subdirs)
		return 0;

	dentry = list_entry(lh, struct dentry, d_u.d_child);
	dput(dentry);
	return 0;
}

static int redirect_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_inode;

	if (!inode || !inode->i_fop || !inode->i_fop->fsync)
		return -EINVAL;

	return inode->i_fop->fsync(file, start, end, datasync);
}

static long redirect_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file->f_inode;

	if (!inode || !inode->i_fop || !inode->i_fop->unlocked_ioctl)
		return -EINVAL;

	return inode->i_fop->unlocked_ioctl(file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long redirect_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file->f_inode;

	if (!inode || !inode->i_fop || !inode->i_fop->unlocked_ioctl)
		return -EINVAL;

	return inode->i_fop->compat_ioctl(file, cmd, arg);
}
#endif

static struct file_operations fast_dir_operations = {
	.read			= generic_read_dir,
	.iterate		= fast_iterate,
	.release		= fast_release_dir,
	.fsync			= redirect_fsync,
	.unlocked_ioctl		= redirect_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= redirect_compat_ioctl,
#endif
};

void try_dir_complete(struct file *f)
{
	struct dentry *dir;
	struct inode *inode;

	if (!f || !f->f_dentry || !d_is_directory(f->f_dentry))
		return;

	dir = f->f_dentry;
	inode = dir->d_inode;

	if (IS_DEADDIR(inode))
		return;

#ifndef CONFIG_DCACHE_COMPLETENESS_FORCE_MISS
	spin_lock(&dir->d_lock);
	if (dir->d_flags & DCACHE_DIR_COMPLETE) {
		fops_put(f->f_op);
		f->f_op = fops_get(&fast_dir_operations);
		INC_STAT(dir_iteratable);
	}
	spin_unlock(&dir->d_lock);
#endif

	f->f_dir_gen = __read_seqcount_begin(&dir->d_complete.d_dir_gen);
	f->f_dir_version = f->f_version;
}

struct dentry;
struct file;
struct qstr;
struct fast_dentry;

#ifdef CONFIG_DCACHE_FAST

extern void partial_signature(path_signature_t *, const unsigned char *,
			      unsigned int);
extern void reverse_signature(path_signature_t *, const unsigned char *,
			      unsigned int);
extern void combine_signature(path_signature_t *, const path_signature_t *);

#if CONFIG_PATH_SIGNATURE_SIZE >= 256
#define SIGNATURE_INIT	{ .state = 0, .r = { 0, 0, 0, 0 }, }
#elif CONFIG_PATH_SIGNATURE_SIZE >= 192
#define SIGNATURE_INIT	{ .state = 0, .r = { 0, 0, 0 }, }
#elif CONFIG_PATH_SIGNATURE_SIZE >= 128
#define SIGNATURE_INIT	{ .state = 0, .r = { 0, 0 }, }
#else
#define SIGNATURE_INIT	{ .state = 0, .r = { 0 }, }
#endif

static inline int
signature_is_zero(path_signature_t *s)
{
	return (s->r[0]
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	      | s->r[1]
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	      | s->r[2]
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	      | s->r[3]
#endif
	      ) == 0;
}

static inline void signature_init(path_signature_t *s)
{
	s->r[0]  = 0;
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	s->r[1]  = 0;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	s->r[2]  = 0;
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	s->r[3]  = 0;
#endif
	s->state = 0;
}

static inline int
signature_cmp(path_signature_t *s1, path_signature_t *s2)
{
	return ((s1->r[0] ^ s2->r[0])
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	     |  (s1->r[1] ^ s2->r[1])
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	     |  (s1->r[2] ^ s2->r[2])
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	     |  (s1->r[3] ^ s2->r[3])
#endif
	     ) != 0;
}

#if 0 /* use a leak-free comparison instead */
static inline int
signature_cmp(path_signature_t *s1, path_signature_t *s2)
{
	return  (s1->r[0] != s2->r[0])
#if CONFIG_PATH_SIGNATURE_SIZE >= 128
	     || (s1->r[1] != s2->r[1])
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 192
	     || (s1->r[2] != s2->r[2])
#endif
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
	     || (s1->r[3] != s2->r[3])
#endif
	     ;
}
#endif

extern struct hlist_bl_head dentry_fast_hashtable[];

#define DCACHE_FAST_HT_SIZE	(1U << CONFIG_DCACHE_FAST_HASHTABLE_ORDER)
#define DCACHE_FAST_HT_MASK	(DCACHE_FAST_HT_SIZE - 1)

static inline
struct hlist_bl_head *d_hash_fast(const path_signature_t *signature)
{
	return &dentry_fast_hashtable[signature->r[0] & DCACHE_FAST_HT_MASK];
}

static inline u32
d_prefix_key(struct fast_dentry *fdentry)
{
	u64 hash = (u64) fdentry / L1_CACHE_BYTES;
	hash += hash >> 8;
	return hash & 0x7fffffff;
}

extern struct hlist_bl_head *d_hash_fast(const path_signature_t *);

static inline struct dentry *real_dentry(struct fast_dentry *fdentry)
{
	return container_of((fdentry), struct dentry, d_fast);
}

static inline int d_unhashed_fast(struct fast_dentry *fdentry)
{
	return hlist_bl_unhashed(&fdentry->d_hash);
}

extern void path_init_fast(struct nameidata *, const char *);
extern void walk_fast(struct nameidata *);
extern void reset_walk_fast(struct nameidata *);
extern void terminate_walk_fast(struct nameidata *);
extern void cache_fast(const struct path *, struct nameidata *);

#ifdef CONFIG_DCACHE_FAST_SYMLINK
extern void walk_fast_symlink(struct nameidata *, struct path *);
extern void cache_fast_symlink(struct nameidata *, unsigned, void *);
extern void alloc_fast_symlink(struct nameidata *, const char *, unsigned int,
			       int);
#endif

extern void d_init_fast(struct fast_dentry *);
extern int d_alloc_fast(struct fast_dentry *, struct fast_dentry *,
			const struct qstr *);
extern void d_free_fast(struct fast_dentry *);

#ifdef CONFIG_DCACHE_FAST_COMPARE_PATH
extern char *d_alloc_external_fast(struct fast_dentry *, unsigned);
extern void d_free_external_fast(const unsigned char *);
#endif

extern void __d_shrink_fast(struct fast_dentry *);
extern void d_shrink_fast(struct fast_dentry *);
extern void __d_rehash_fast(struct fast_dentry *, struct hlist_bl_head *);
extern void _d_rehash_fast(struct fast_dentry *);
extern void d_rehash_fast(struct fast_dentry *);

extern seqcount_t invalidate_seq;
extern void start_invalidate_fast(void);
extern void end_invalidate_fast(void);
extern void __d_invalidate_fast(struct vfsmount *, struct dentry *);

extern void fast_dcache_init(void);

extern int link_path_walk_fast(int, const char *, unsigned int,
			       struct nameidata *);

struct open_flags;
extern int do_open_fast(struct nameidata *, struct file *,
			const struct open_flags *, int *, struct filename *);

static __always_inline void
last_norm_component(struct qstr *name, const unsigned char *start)
{
	register const unsigned char *p1;
	register const unsigned char *p2 = name->name;
	register unsigned len, depth = 0;

	do {
		for (p1 = p2; p1 > start && *(p1 - 1) == '/'; p1--);
		for (p2 = p1; p2 > start && *(p2 - 1) != '/'; p2--);
		len = p2 - p1;
		if (p2 < p1 && p2[0] == '.') switch (len) {
			case 1:
				continue;
			case 2:
				if (p2[1] == '.') {
					depth++;
					continue;
				}
		}
		if (!depth--)
			break;
	} while (len);

	name->name = p2;
	name->len = p1 - p2;
}

extern int consume_path(struct nameidata *, const char **);
extern int follow_negative(struct nameidata *, const char **);
extern int follow_notdir(struct nameidata *, const char **);

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES

static inline struct deep_dentry *real_deep_dentry(struct fast_dentry *fdentry)
{
	return container_of((fdentry), struct deep_dentry, d_fast);
}

extern void deep_dentry_init(void);

extern void __d_shrink_deep(struct fast_dentry *);
extern void d_shrink_deep(struct dentry *);

#ifdef CONFIG_DCACHE_FAST_DEEP_DENTRIES
extern int alloc_deep_dentries(struct nameidata *, const char **,
			       unsigned);
#endif

#endif /* CONFIG_DCACHE_FAST_DEEP_DENTRIES */

#endif /* CONFIG_DCACHE_FAST */

#ifdef CONFIG_DCACHE_COMPLETENESS

static inline void d_init_complete(struct dir_complete *complete)
{
	complete->d_ino = 0;
}

extern void d_instantiate_complete(struct dentry *);

extern void maybe_d_alloc_for_readdir(struct file *, const char *, int,
				      u64, unsigned int);

extern void try_mark_dir_complete(struct file *file);

#define d_can_complete(dentry)						\
	(d_is_directory(dentry) &&					\
	 likely(!((dentry)->d_flags & DCACHE_OP_REVALIDATE) &&		\
		!!((dentry)->d_sb->s_bdev)))

extern void try_dir_complete(struct file *);

#endif /* CONFIG_DCACHE_COMPLETENESS */

#define d_debug(level, ...) do {} while (0)

#ifdef CONFIG_DCACHE_DEBUG
#undef d_debug

#if defined(CONFIG_DCACHE_FAST) && !defined(CONFIG_DCACHE_FAST_COMPARE_PATH)
#if CONFIG_PATH_SIGNATURE_SIZE >= 256
#  define PATH_SIGNATURE_FMT	"[%u] %016llx %016llx %016llx %016llx"
#  define PATH_SIGNATURE_PRINTK(s)	(s).state, (s).r[0], (s).r[1], (s).r[2], (s).r[3]
#elif CONFIG_PATH_SIGNATURE_SIZE >= 192
#  define PATH_SIGNATURE_FMT	"[%u] %016llx %016llx %016llx"
#  define PATH_SIGNATURE_PRINTK(s)	(s).state, (s).r[0], (s).r[1], (s).r[2]
#elif CONFIG_PATH_SIGNATURE_SIZE >= 128
#  define PATH_SIGNATURE_FMT	"[%u] %016llx %016llx"
#  define PATH_SIGNATURE_PRINTK(s)	(s).state, (s).r[0], (s).r[1]
#else
#  define PATH_SIGNATURE_FMT	"[%u] %016llx"
#  define PATH_SIGNATURE_PRINTK(s)	(s).state, (s).index, (s).r[0]
#endif
#endif /* !CONFIG_DCACHE_FAST_COMPARE_PATH */

#define DENTRY_NAME_FMT "%p(%s)"
#define DENTRY_NAME_PRINTK(dentry) (dentry), (dentry)->d_name.name

#ifdef CONFIG_DCACHE_DEBUG_ERROR
#  define DCACHE_DEBUG_E 1
#else
#  define DCACHE_DEBUG_E 0
#endif
#ifdef CONFIG_DCACHE_DEBUG_INFO
#  define DCACHE_DEBUG_I 1
#else
#  define DCACHE_DEBUG_I 0
#endif
#ifdef CONFIG_DCACHE_DEBUG_DETAIL
#  define DCACHE_DEBUG_D 1
#else
#  define DCACHE_DEBUG_D 0
#endif
#define DCACHE_PRINTK_LEVEL KERN_SOH CONFIG_DCACHE_PRINTK_LEVEL
#define d_debug(level, ...)						\
	do {								\
		if (DCACHE_DEBUG_##level)				\
			printk(DCACHE_PRINTK_LEVEL "[DCACHE] " __VA_ARGS__);	\
	} while (0)

#endif /* CONFIG_DCACHE_DEBUG */

#ifdef CONFIG_DCACHE_AGGRESSIVE_NEGATIVE
extern void __d_create_negative(struct dentry *);
#endif

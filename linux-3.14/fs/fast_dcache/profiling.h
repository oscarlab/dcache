
#ifdef CONFIG_DCACHE_FAST_PROFILING

#define USE_RDTSCP

#ifdef USE_GETTIMEOFDAY

struct profile_time { u64 start, total; };

#define DECLARE_TIME(var)	struct profile_time __time_##var = { 0, 0 }

#define TIME_START(var)						\
	do {							\
		struct timespec ts;				\
		__getnstimeofday(&ts);				\
		__time_##var.start = ts.tv_sec * 1000000000ULL + ts.tv_nsec;	\
	} while (0)

#define TIME_END(var)						\
	do {							\
		struct timespec ts;				\
		if (!__time_##var.start) break;			\
		__getnstimeofday(&ts);				\
		__time_##var.total +=				\
			ts.tv_sec * 1000000000ULL + ts.tv_nsec -	\
			__time_##var.start;			\
		__time_##var.start = 0;				\
	} while (0)

#define TIME_VALUE(var) (__time_##var.total)

#endif /* USE_GETTIMEOFDAY */

#ifdef USE_RDTSCP

#ifdef __i386__
#define RDTSCP_DIRTY "eax", "ebx", "ecx", "edx", "memory"
#elif __x86_64__
#define RDTSCP_DIRTY "rbx", "rcx", "rdx", "memory"
#else
#error unknown platform
#endif

struct profile_time { u64 start, total; };

#define DECLARE_TIME(var)	struct profile_time __time_##var = { 0, 0 }

#define TIME_START(var)					\
	do {							\
		register u64 tsc;			\
		asm volatile(			\
			     "RDTSCP\n\t"			\
			     "shl $32, %%rdx\n\t"	\
			     "or %%rdx, %0"		\
			     : "=a" (tsc)		\
			     :: RDTSCP_DIRTY);			\
		__time_##var.start =				\
			tsc;				\
	} while (0)

#define TIME_END(var)						\
	do {							\
		register u64 tsc;				\
		WARN(!__time_##var.start, "%d", __LINE__);	\
		if (!__time_##var.start) break;			\
		asm volatile("RDTSCP\n\t"			\
			     "shl $32, %%rdx\n\t"	\
			     "or %%rdx, %0"		\
			     : "=a" (tsc)		\
			     :: RDTSCP_DIRTY);			\
		__time_##var.total +=				\
			tsc - __time_##var.start;		\
		__time_##var.start = 0;				\
	} while (0)

#define TIME_VALUE(var) (__time_##var.total)

#endif /* USE_RDTSCP */

#ifdef USE_RDTSC

#ifdef __i386__
#define RDTSC_DIRTY "eax", "ebx", "ecx", "edx", "memory"
#elif __x86_64__
#define RDTSC_DIRTY "rax", "rbx", "rcx", "rdx", "memory"
#else
#error unknown platform
#endif

#define RDTSC_UNIT	(1000000)

struct profile_time { u64 start, total; };

#define DECLARE_TIME(var)	struct profile_time __time_##var = { 0, 0 }

#define TIME_START(var)					\
	do {							\
		register unsigned high, low;			\
		asm volatile("CPUID\n\t"			\
			     "RDTSC\n\t"			\
			     "mov %%edx, %0\n\t"		\
			     "mov %%eax, %1\n\t"		\
			     : "=r" (high), "=r"(low)		\
			     :: RDTSC_DIRTY);			\
		__time_##var.start =				\
			(u64) (((u64) high << 32) | low) / RDTSC_UNIT;	\
	} while (0)

#define TIME_END(var)						\
	do {							\
		register unsigned high, low;			\
		if (!__time_##var.start) break;			\
		asm volatile("RDTSC\n\t"			\
			     "mov %%edx, %0\n\t"		\
			     "mov %%eax, %1\n\t"		\
			     "CPUID\n\t"			\
			     : "=r" (high), "=r"(low)		\
			     :: RDTSC_DIRTY);			\
		__time_##var.total +=				\
			(u64) (((u64) high << 32) | low) / RDTSC_UNIT -	\
			__time_##var.start;			\
		__time_##var.start = 0;				\
	} while (0)

#define TIME_VALUE(var) (__time_##var.total)

#endif /* USE_RDTSC */

#ifdef USE_JIFFIES

struct profile_time { u64 start, total; };

#define DECLARE_TIME(var)	struct profile_time __time_##var = { 0, 0 }

#define TIME_START(var)						\
	do {							\
		__time_##var.start =				\
			jiffies_to_nsecs(get_jiffies_64());	\
	} while (0)

#define TIME_END(var)						\
	do {							\
		if (!__time_##var.start) break;			\
		__time_##var.total +=				\
			jiffies_to_nsecs(get_jiffies_64()) -	\
			__time_##var.start;			\
		__time_##var.start = 0;				\
	} while (0)

#define TIME_VALUE(var) (__time_##var.total)

#endif /* USE_JIFFIES */

#define PROFILE_PRINT_LEVEL KERN_DEBUG

#define d_profile(...)						\
	printk(PROFILE_PRINT_LEVEL "[DCACHE] " __VA_ARGS__)

#else

#define DECLARE_TIME(var)

#define TIME_START(var) do {} while (0)
#define TIME_END(var) do {} while (0)

#define TIME_VALUE(var) (0)

#define d_profile(...) do {} while (0)

#endif

#include <linux/limits.h>
#include <linux/random.h>
#include "mhash.h"

#define MHASH_MAX_LEN	((PATH_MAX - 1)/(MHASH_L / 8) + 1)

typedef struct {
	u64 lo;
	u64 hi[MHASH_RAND_LEN];
} __attribute__((packed)) mhash_rand_t;

static mhash_rand_t mhash_random[MHASH_MAX_LEN + 1];

void __init mhash_init(void)
{
	get_random_bytes(mhash_random, sizeof(mhash_random));
}

#if MHASH_K == 320
static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u64 msg)
{
/*
 *          ||                            | tmp0 | || | tmp? |
 *          ||                   | tmp1 | | tmp4 | ||
 *          ||          | tmp2 | | tmp5 |          ||
 *          || | tmp3 | | tmp6 |                   ||
 * | tmp? | || | tmp7 |                            ||
 */
	register u64 tmp[8];

	__asm__ __volatile__ (
		"movq %8, %%rax\n\t"
		"mulq %9\n\t"
		"movq %%rdx, %0\n\t"
		"movq %8, %%rax\n\t"
		"mulq %10\n\t"
		"movq %%rdx, %1\n\t"
		"movq %%rax, %4\n\t"
		"movq %8, %%rax\n\t"
		"mulq %11\n\t"
		"movq %%rdx, %2\n\t"
		"movq %%rax, %5\n\t"
		"movq %8, %%rax\n\t"
		"mulq %12\n\t"
		"movq %%rdx, %3\n\t"
		"movq %%rax, %6\n\t"
		"movq %8, %%rax\n\t"
		"mulq %13\n\t"
		"movq %%rax, %7\n\t"
		"addq %4, %0\n\t"
		"adcq %5, %1\n\t"
		"adcq %6, %2\n\t"
		"adcq %7, %3\n\t"
		: "=r"(tmp[0]), "=r"(tmp[1]), "=r"(tmp[2]), "=r"(tmp[3]),
		  "=r"(tmp[4]), "=r"(tmp[5]), "=r"(tmp[6]), "=r"(tmp[7])
		: "r"(msg), "r"(kptr->lo), "r"(kptr->hi[0]), "r"(kptr->hi[1]),
		  "r"(kptr->hi[2]), "r"(kptr->hi[3])
		: "%rax", "%rdx"
	);

	res[0] ^= tmp[0];
	res[1] ^= tmp[1];
	res[2] ^= tmp[2];
	res[3] ^= tmp[3];
}
#elif MHASH_K == 256
static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u64 msg)
{
/*
 *          ||                   | tmp0 | || | tmp? |
 *          ||          | tmp1 | | tmp3 | ||
 *          || | tmp2 | | tmp4 |          ||
 * | tmp? | || | tmp5 |                   ||
 */
	register u64 tmp[6];

	__asm__ __volatile__ (
		"movq %6, %%rax\n\t"
		"mulq %7\n\t"
		"movq %%rdx, %0\n\t"
		"movq %6, %%rax\n\t"
		"mulq %8\n\t"
		"movq %%rdx, %1\n\t"
		"movq %%rax, %3\n\t"
		"movq %6, %%rax\n\t"
		"mulq %9\n\t"
		"movq %%rdx, %2\n\t"
		"movq %%rax, %4\n\t"
		"movq %6, %%rax\n\t"
		"mulq %10\n\t"
		"movq %%rax, %5\n\t"
		"addq %3, %0\n\t"
		"adcq %4, %1\n\t"
		"adcq %5, %2\n\t"
		: "=r"(tmp[0]), "=r"(tmp[1]), "=r"(tmp[2]), "=r"(tmp[3]),
		  "=r"(tmp[4]), "=r"(tmp[5])
		: "r"(msg), "r"(kptr->lo), "r"(kptr->hi[0]), "r"(kptr->hi[1]),
		  "r"(kptr->hi[2])
		: "%rax", "%rdx"
	);

	res[0] ^= tmp[0];
	res[1] ^= tmp[1];
	res[2] ^= tmp[2];
}
#elif MHASH_K == 192
static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u64 msg)
{
/*
 *          ||          | tmp0 | || | tmp? |
 *          || | tmp1 | | tmp2 | ||
 * | tmp? | || | tmp3 |          ||
 */
	register u64 tmp[4];

	__asm__ __volatile__ (
		"movq %4, %%rax\n\t"
		"mulq %5\n\t"
		"movq %%rdx, %0\n\t"
		"movq %4, %%rax\n\t"
		"mulq %6\n\t"
		"movq %%rdx, %1\n\t"
		"movq %%rax, %2\n\t"
		"movq %4, %%rax\n\t"
		"mulq %7\n\t"
		"movq %%rax, %3\n\t"
		"addq %2, %0\n\t"
		"adcq %3, %1\n\t"
		: "=r"(tmp[0]), "=r"(tmp[1]), "=r"(tmp[2]), "=r"(tmp[3])
		: "r"(msg), "r"(kptr->lo), "r"(kptr->hi[0]), "r"(kptr->hi[1])
		: "%rax", "%rdx"
	);

	res[0] ^= tmp[0];
	res[1] ^= tmp[1];
}
#elif MHASH_K == 128
void calGFstep(u64 *res, mhash_rand_t *kptr, u32 msg)
{
/*
 *          || | tmp0 | || | tmp? |
 * | tmp? | || | tmp1 | ||
 */
	register u64 tmp[2];

	__asm__ __volatile__ (
		"movq %2, %%rax\n\t"
		"mulq %3\n\t"
		"movq %%rdx, %0\n\t"
		"movq %2, %%rax\n\t"
		"mulq %4\n\t"
		"movq %%rax, %1\n\t"
		"addq %1, %0\n\t"
		: "=r"(tmp[0]), "=r"(tmp[1])
		: "r"(msg), "r"(kptr->lo), "r"(kptr->hi[0])
		: "%rax", "%rdx"
	);

	res[0] ^= tmp[0];
}
#endif /* MHASH_K ==  */

unsigned int mhash_hash(const unsigned char *name, unsigned int len, u64 *res,
			unsigned int state)
{
	register mhash_rand_t *kptr = &mhash_random[state + 1];
	u64 *mptr = (u64 *)name;
	unsigned int rem = len % 8;
	len /= 8;

	if (!state) {
		res[0] = mhash_random[0].hi[0];
#if MHASH_RAND_LEN >= 2
		res[1] = mhash_random[0].hi[1];
#endif
#if MHASH_RAND_LEN >= 3
		res[2] = mhash_random[0].hi[2];
#endif
#if MHASH_RAND_LEN >= 4
		res[3] = mhash_random[0].hi[3];
#endif
	}

	while (len--) {
		calGFstep(res, kptr, *mptr);
		mptr++;
		kptr++;
	}

	if (rem) {
#if defined(__LITTLE_ENDIAN)
		u64 last = *mptr & ((1ULL << rem * 8) - 1);
#elif defined(__BIG_ENDIAN)
		u64 last = *mptr & ~((1ULL << (64 - rem * 8) - 1);
#else
		BUG();
#endif
		calGFstep(res, kptr, last);
		kptr++;
	}

	return kptr - &mhash_random[1];
}

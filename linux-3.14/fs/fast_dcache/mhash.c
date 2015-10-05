#include <linux/limits.h>
#include <linux/random.h>
#include "mhash.h"

#define MHASH_MAX_LEN	(PATH_MAX/(MHASH_L/8)+1)

static u64 mhash_random[(MHASH_MAX_LEN+1)*(MHASH_RAND_LEN+1)] __read_mostly;

void __init mhash_init(void)
{
	get_random_bytes(mhash_random, sizeof(mhash_random));
}

#define MUL32(i1, i2)	((u64)(u32)(i1) * (u32)(i2))
#define MUL64(i1, i2)	((u64)(i1) * (u32)(i2))
#define HI32(i)		((i) >> 32)
#define LO32(i)		((i) & 0xFFFFFFFF)
#define LO2HI32(i)	((i) << 32)
#define ADD64C(i1, i2, carry)						\
	do {								\
		register u64 _i = (i1);					\
		if (carry) (i1)++;					\
		(i1) += (i2);						\
		carry = ((i1) < _i);					\
	} while (0)

#if MHASH_K == 288
static inline
void calGFstep(u64 *res, u64 *kptr, u32 msg)
{
	register u64 tmp[4];
	register u64 key[4] = { kptr[0], kptr[1], kptr[2], kptr[3] };
	register u32 lo = LO32(kptr[4]);
	register bool carry = false;

	tmp[0] = MUL64(key[0], msg);
	tmp[1] = MUL64(key[1], msg);
	tmp[2] = MUL64(key[2], msg);
	tmp[3] = MUL64(key[3], msg);

	ADD64C(tmp[0], HI32(MUL32(lo, msg)), carry);
	ADD64C(tmp[1], HI32(MUL32(HI32(key[0]), msg)), carry);
	ADD64C(tmp[2], HI32(MUL32(HI32(key[1]), msg)), carry);
	ADD64C(tmp[3], HI32(MUL32(HI32(key[2]), msg)), carry);

	res[0] ^= tmp[0];
	res[1] ^= tmp[1];
	res[2] ^= tmp[2];
	res[3] ^= tmp[3];
}
#elif MHASH_K == 224
static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u32 msg)
{
	register mhash_rand_t tmp;
	register mhash_rand_t key = *kptr;
	register bool carry = false;

	tmp.hi[0] = MUL64(key.hi[0], msg);
	tmp.hi[1] = MUL64(key.hi[1], msg);
	tmp.hi[2] = MUL64(key.hi[2], msg);

	ADD64C(tmp.hi[0], HI32(MUL32(key.lo, msg)), carry);
	ADD64C(tmp.hi[1], HI32(MUL32(HI32(key.hi[0]), msg)), carry);
	ADD64C(tmp.hi[2], HI32(MUL32(HI32(key.hi[1]), msg)), carry);

	res[0] ^= tmp.hi[0];
	res[1] ^= tmp.hi[1];
	res[2] ^= tmp.hi[2];
}
#elif MHASH_K == 160
static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u32 msg)
{
	register mhash_rand_t tmp;
	register mhash_rand_t key = *kptr;
	register bool carry = false;

	tmp.hi[0] = MUL64(key.hi[0], msg);
	tmp.hi[1] = MUL64(key.hi[1], msg);

	ADD64C(tmp.hi[0], HI32(MUL32(key.lo, msg)), carry);
	ADD64C(tmp.hi[1], HI32(MUL32(HI32(key.hi[0]), msg)), carry);

	res[0] ^= tmp.hi[0];
	res[1] ^= tmp.hi[1];
}
#elif MHASH_K == 96
void calGFstep(u64 *res, mhash_rand_t *kptr, u32 msg)
{
	register mhash_rand_t tmp;
	register mhash_rand_t key = *kptr;

	tmp.hi[0] = MUL64(key.hi[0], msg);
	tmp.hi[0] += HI32(MUL32(key.lo, msg));

	res[0] ^= tmp.hi[0];
}
#endif /* MHASH_K == 96 */

unsigned int mhash_hash(const unsigned char *name, unsigned int len, u64 *res,
			unsigned int state)
{
	register u64 *kptr = &mhash_random[(state+1)*(MHASH_RAND_LEN+1)];
	u32 *mptr = (u32 *)name;
	unsigned int rem = len % 4;
	len /= 4; // Increment in 32-bit strides

	if (!state) {
		res[0] = mhash_random[0];
#if MHASH_RAND_LEN >= 2
		res[1] = mhash_random[1];
#endif
#if MHASH_RAND_LEN >= 3
		res[2] = mhash_random[2];
#endif
#if MHASH_RAND_LEN >= 4
		res[3] = mhash_random[3];
#endif
	}

	while (len--) {
		calGFstep(res, kptr, *mptr);
		mptr++;
		kptr += MHASH_RAND_LEN+1;
		state++;
	}

	if (rem) {
#if defined(__LITTLE_ENDIAN)
		u32 last = *mptr & ((1UL << rem * 8) - 1);
#elif defined(__BIG_ENDIAN)
		u32 last = *mptr & ~((1UL << (32 - rem * 8) - 1);
#else
		BUG();
#endif
		calGFstep(res, kptr, last);
		state++;
	}

	return state;
}

void mhash_prepare(unsigned int state)
{
	if (!state)
		prefetch(mhash_random);
	else
		prefetch(&mhash_random[(state+1)*(MHASH_RAND_LEN+1)]);
}

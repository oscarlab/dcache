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

#include <linux/limits.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <asm/i387.h>
#include "mhash.h"

int mhash_use_avx2 __read_mostly = 0;

/* Collect lookup statistics. */
struct mhash_avx2_usage_t mhash_avx2_usage;

static DEFINE_PER_CPU(long, avx2);
static DEFINE_PER_CPU(long, fallback);

#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_mhash_avx2_usage(ctl_table *table, int write, void __user *buffer,
			  size_t *lenp, loff_t *ppos)
{
	int i;
	struct mhash_avx2_usage_t usage = { 0, 0 };
	for_each_possible_cpu(i) {
		usage.avx2	+= per_cpu(avx2,	i);
		usage.fallback	+= per_cpu(fallback,	i);
	}
	mhash_avx2_usage = usage;
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#endif

typedef struct {
	u64 hi[4];
	u32 lo;
} __attribute__((aligned(64))) mhash_rand_t;

static mhash_rand_t mhash_random[(PATH_MAX / (MHASH_L / 8))];

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

static inline
void calGFstep(u64 *res, mhash_rand_t *kptr, u32 msg)
{
	mhash_rand_t key = *kptr;
	register u64 tmp[4];
	register bool carry = false;

	tmp[0] = MUL64(key.hi[0], msg);
	tmp[1] = MUL64(key.hi[1], msg);
	tmp[2] = MUL64(key.hi[2], msg);
	tmp[3] = MUL64(key.hi[3], msg);

#if 0
	ADD64C(tmp[0], HI32(MUL32(lo, msg)), carry);
	ADD64C(tmp[1], HI32(MUL32(HI32(hi[0]), msg)), carry);
	ADD64C(tmp[2], HI32(MUL32(HI32(hi[1]), msg)), carry);
	ADD64C(tmp[3], HI32(MUL32(HI32(hi[2]), msg)), carry);
#endif
	tmp[0] += HI32(MUL32(key.lo, msg));
	tmp[1] += HI32(MUL32(HI32(key.hi[0]), msg));
	tmp[2] += HI32(MUL32(HI32(key.hi[1]), msg));
	tmp[3] += HI32(MUL32(HI32(key.hi[2]), msg));

	res[0] ^= tmp[0];
	res[1] ^= tmp[1];
	res[2] ^= tmp[2];
	res[3] ^= tmp[3];
}

extern unsigned int mhash_hash_avx2(const char *, unsigned int, mhash_rand_t *,
				    u64 *, unsigned int);

unsigned int mhash_hash(const unsigned char *name, unsigned int len, u64 *res,
			unsigned int state)
{
	register mhash_rand_t *kptr = &mhash_random[state + 1];
	u32 *mptr = (u32 *)name;
	unsigned int rem = len % 4;

	if (likely(mhash_use_avx2)) {
		if (!((u64) res % 32)) {
			this_cpu_inc(avx2);
			preempt_disable();
			state = mhash_hash_avx2(name, len, mhash_random, res, state);
			preempt_enable();
			return state;
		}

		this_cpu_inc(fallback);
	}

	if (!state) {
		res[0] = mhash_random[0].hi[0];
		res[1] = mhash_random[0].hi[1];
		res[2] = mhash_random[0].hi[2];
		res[3] = mhash_random[0].hi[3];
	}

	len /= 4; // Increment in 32-bit strides

	while (len--) {
		calGFstep(res, kptr, *mptr);
		kptr++;
		mptr++;
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

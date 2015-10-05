#ifndef _LINUX_MHASH_H_
#define _LINUX_MHASH_H_

#include <linux/types.h>

#define	MHASH_HASH_LEN CONFIG_PATH_SIGNATURE_SIZE

#if defined(CONFIG_PATH_SIGNATURE_MHASH64) || defined(CONFIG_PATH_SIGNATURE_MHASHROB)
#define MHASH_L		64
#else
#define MHASH_L		32
#endif
#define MHASH_K		(MHASH_HASH_LEN+MHASH_L)
#define MHASH_RAND_LEN	(MHASH_HASH_LEN/64)

void mhash_init(void);
void mhash_prepare(unsigned int state);
unsigned int mhash_hash(const unsigned char *name, unsigned int len, u64 *res,
			unsigned int state);

#endif

/*
 * jelkins.h
 * See linux/lib/jelkins-old.c, linux/lib/jelkins-lookup3.c,
 * linux/lib/jelkins-spooky.c for license and changes.
 */
#ifndef _LINUX_JELKINS_H_
#define _LINUX_JELKINS_H_

#include <linux/types.h>

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_OLD
u32 jelkins_old_hash(const unsigned char *k, int length, u32 initval);
#endif

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_LOOKUP3
u32 jelkins_lookup3_hashword(const u32 *k, int length, u32 initval);
void jelkins_lookup3_hashword64(const u32 *k, int length, u32 *pc, u32 *pb);
u32 jelkins_lookup3_hash(const void *key, int length, u32 initval);
void jelkins_lookup3_hash64(const void *key, int length, u32 *pc, u32 *pb);
u32 jelkins_lookup3_hashbig(const void *key, int length, u32 initval);
#endif

#ifdef CONFIG_PATH_SIGNATURE_JELKINS_SPOOKY

// number of u64's in internal state
#define SC_NUMVARS	12

// size of the internal state
#define SC_BLOCKSIZE	SC_NUMVARS*8

// size of buffer of unhashed data, in bytes
#define SC_BUFSIZE	2*SC_BLOCKSIZE

//
// sc_const: a constant which:
//  * is not zero
//  * is odd
//  * is a not-very-regular mix of 1's and 0's
//  * does not need any other special mathematical properties
//
#define SC_CONST	0xdeadbeefdeadbeefLL

void jelkins_spooky_hashshort(const void *message, int length, u64 *hash1, u64 *hash2);
void jelkins_spooky_hash128(const void *message, int length, u64 *hash1, u64 *hash2);

struct jelkins_spooky
{
	u64 data[2*SC_NUMVARS];	// unhashed data, for partial messages
	u64 state[SC_NUMVARS];	// internal state of the hash
	int length;		// total length of the input so far
	u8  remainder;		// length of unhashed data stashed in m_data
};

void jelkins_spooky_init(struct jelkins_spooky *m, u64 seed1, u64 seed2);
void jelkins_spooky_update(struct jelkins_spooky *m, const void *message, int length);
void jelkins_spooky_final(struct jelkins_spooky *m, u64 *hash1, u64 *hash2);

#endif

#endif /* _LINUX_JELKINS_H_ */

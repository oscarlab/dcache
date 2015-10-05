// Spooky Hash
// A 128-bit noncryptographic hash, for checksums and table lookup
// By Bob Jenkins.  Public domain.
//   Oct 31 2010: published framework, disclaimer ShortHash isn't right
//   Nov 7 2010: disabled ShortHash
//   Oct 31 2011: replace end, short_mix, short_end, enable ShortHash again
//   April 10 2012: buffer overflow on platforms without unaligned reads
//   July 12 2012: was passing out variables in final to in/out in short
//   July 30 2012: I reintroduced the buffer overflow
//   August 5 2012: SpookyV2: d = should be d += in short hash, and remove extra mix from long hash

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/memory.h>
#include "jelkins.h"

static inline u64 rot64(u64 x, int k)
{
    return (x << k) | (x >> (64 - k));
}

//
// This is used if the input is 96 bytes long or longer.
//
// The internal state is fully overwritten every 96 bytes.
// Every input bit appears to cause at least 128 bits of entropy
// before 96 other bytes are combined, when run forward or backward
//   For every input bit,
//   Two inputs differing in just that input bit
//   Where "differ" means xor or subtraction
//   And the base value is random
//   When run forward or backwards one mix
// I tried 3 pairs of each; they all differed by at least 212 bits.
//
#define mix(data,s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11) \
do { \
	s0 += (data)[0];	s2 ^= s10;	s11 ^= s0;	s0 = rot64(s0,11);	s11 += s1;	\
	s1 += (data)[1];	s3 ^= s11;	s0 ^= s1;	s1 = rot64(s1,32);	s0 += s2;	\
	s2 += (data)[2];	s4 ^= s0;	s1 ^= s2;	s2 = rot64(s2,43);	s1 += s3;	\
	s3 += (data)[3];	s5 ^= s1;	s2 ^= s3;	s3 = rot64(s3,31);	s2 += s4;	\
	s4 += (data)[4];	s6 ^= s2;	s3 ^= s4;	s4 = rot64(s4,17);	s3 += s5;	\
	s5 += (data)[5];	s7 ^= s3;	s4 ^= s5;	s5 = rot64(s5,28);	s4 += s6;	\
	s6 += (data)[6];	s8 ^= s4;	s5 ^= s6;	s6 = rot64(s6,39);	s5 += s7;	\
	s7 += (data)[7];	s9 ^= s5;	s6 ^= s7;	s7 = rot64(s7,57);	s6 += s8;	\
	s8 += (data)[8];	s10 ^= s6;	s7 ^= s8;	s8 = rot64(s8,55);	s7 += s9;	\
	s9 += (data)[9];	s11 ^= s7;	s8 ^= s9;	s9 = rot64(s9,54);	s8 += s10;	\
	s10 += (data)[10];	s0 ^= s8;	s9 ^= s10;	s10 = rot64(s10,22);	s9 += s11;	\
	s11 += (data)[11]; 	s1 ^= s9;	s10 ^= s11;	s11 = rot64(s11,46);	s10 += s0;	\
} while (0)

//
// mix all 12 inputs together so that h0, h1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of h0, h1 flip
// For every input bit,
// with probability 50 +- .3%
// For every pair of input bits,
// with probability 50 +- 3%
//
// This does not rely on the last mix() call having already mixed some.
// Two iterations was almost good enough for a 64-bit result, but a
// 128-bit result is reported, so end() does three iterations.
//
#define end_partial(h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11) \
do { \
	h11+= h1;	h2 ^= h11;	h1 = rot64(h1,44);	\
	h0 += h2;	h3 ^= h0;	h2 = rot64(h2,15);	\
	h1 += h3;	h4 ^= h1;	h3 = rot64(h3,34);	\
	h2 += h4;	h5 ^= h2;	h4 = rot64(h4,21);	\
	h3 += h5;	h6 ^= h3;	h5 = rot64(h5,38);	\
	h4 += h6;	h7 ^= h4;	h6 = rot64(h6,33);	\
	h5 += h7;	h8 ^= h5;	h7 = rot64(h7,10);	\
	h6 += h8;	h9 ^= h6;	h8 = rot64(h8,13);	\
	h7 += h9;	h10^= h7;	h9 = rot64(h9,38);	\
	h8 += h10;	h11^= h8;	h10= rot64(h10,53);	\
	h9 += h11;	h0 ^= h9;	h11= rot64(h11,42);	\
	h10+= h0;	h1 ^= h10;	h0 = rot64(h0,54);	\
} while (0)

#define end(data,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11) \
do { \
	end_partial(h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11); \
	end_partial(h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11); \
	end_partial(h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11); \
} while (0)

//
// The goal is for each bit of the input to expand into 128 bits of 
//   apparent entropy before it is fully overwritten.
// n trials both set and cleared at least m bits of h0 h1 h2 h3
//   n: 2   m: 29
//   n: 3   m: 46
//   n: 4   m: 57
//   n: 5   m: 107
//   n: 6   m: 146
//   n: 7   m: 152
// when run forwards or backwards
// for all 1-bit and 2-bit diffs
// with diffs defined by either xor or subtraction
// with a base of all zeros plus a counter, or plus another bit, or random
//
#define short_mix(h0,h1,h2,h3) \
do { \
	h2 = rot64(h2,50);  h2 += h3;  h0 ^= h2;	\
	h3 = rot64(h3,52);  h3 += h0;  h1 ^= h3;	\
	h0 = rot64(h0,30);  h0 += h1;  h2 ^= h0;	\
	h1 = rot64(h1,41);  h1 += h2;  h3 ^= h1;	\
	h2 = rot64(h2,54);  h2 += h3;  h0 ^= h2;	\
	h3 = rot64(h3,48);  h3 += h0;  h1 ^= h3;	\
	h0 = rot64(h0,38);  h0 += h1;  h2 ^= h0;	\
	h1 = rot64(h1,37);  h1 += h2;  h3 ^= h1;	\
	h2 = rot64(h2,62);  h2 += h3;  h0 ^= h2;	\
	h3 = rot64(h3,34);  h3 += h0;  h1 ^= h3;	\
	h0 = rot64(h0,5);   h0 += h1;  h2 ^= h0;	\
	h1 = rot64(h1,36);  h1 += h2;  h3 ^= h1;	\
} while (0)

//
// mix all 4 inputs together so that h0, h1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of h0, h1 flip
// For every input bit,
// with probability 50 +- .3% (it is probably better than that)
// For every pair of input bits,
// with probability 50 +- .75% (the worst case is approximately that)
//
#define short_end(h0,h1,h2,h3) \
do { \
	h3 ^= h2;  h2 = rot64(h2,15);  h3 += h2;	\
	h0 ^= h3;  h3 = rot64(h3,52);  h0 += h3;	\
	h1 ^= h0;  h0 = rot64(h0,26);  h1 += h0;	\
	h2 ^= h1;  h1 = rot64(h1,51);  h2 += h1;	\
	h3 ^= h2;  h2 = rot64(h2,28);  h3 += h2;	\
	h0 ^= h3;  h3 = rot64(h3,9);   h0 += h3;	\
	h1 ^= h0;  h0 = rot64(h0,47);  h1 += h0;	\
	h2 ^= h1;  h1 = rot64(h1,54);  h2 += h1;	\
	h3 ^= h2;  h2 = rot64(h2,32);  h3 += h2;	\
	h0 ^= h3;  h3 = rot64(h3,25);  h0 += h3;	\
	h1 ^= h0;  h0 = rot64(h0,63);  h1 += h0;	\
} while (0)

#define ALLOW_UNALIGNED_READS 1

//
// short hash ... it could be used on any message, 
// but it's used by Spooky just for short messages.
//
void jelkins_spooky_hashshort(
    const void *message,
    int length,
    u64 *hash1,
    u64 *hash2)
{
	u64 buf[2*SC_NUMVARS];
	union
	{
		const u8 *p8;
		u32 *p32;
		u64 *p64;
		int i;
	} u;
	size_t remainder = length%32;
	u64 a = *hash1;
	u64 b = *hash2;
	u64 c = SC_CONST;
	u64 d = SC_CONST;

	u.p8 = (const u8 *)message;

	if (!ALLOW_UNALIGNED_READS && (u.i & 0x7))
	{
		memcpy(buf, message, length);
		u.p64 = buf;
	}

	if (length > 15)
	{
		const u64 *end = u.p64 + (length/32)*4;

		// handle all complete sets of 32 bytes
		for (; u.p64 < end; u.p64 += 4)
		{
			c += u.p64[0];
			d += u.p64[1];
			short_mix(a,b,c,d);
			a += u.p64[2];
			b += u.p64[3];
		}

		// handle the case of 16+ remaining bytes.
		if (remainder >= 16)
		{
			c += u.p64[0];
			d += u.p64[1];
			short_mix(a,b,c,d);
			u.p64 += 2;
			remainder -= 16;
		}
	}

	// handle the last 0..15 bytes, and its length
	d += ((u64)length) << 56;
	switch (remainder)
	{
		case 15:
			d += ((u64)u.p8[14]) << 48;
		case 14:
			d += ((u64)u.p8[13]) << 40;
		case 13:
			d += ((u64)u.p8[12]) << 32;
		case 12:
			d += u.p32[2];
			c += u.p64[0];
			break;
		case 11:
			d += ((u64)u.p8[10]) << 16;
		case 10:
			d += ((u64)u.p8[9]) << 8;
		case 9:
			d += (u64)u.p8[8];
		case 8:
			c += u.p64[0];
			break;
		case 7:
			c += ((u64)u.p8[6]) << 48;
		case 6:
			c += ((u64)u.p8[5]) << 40;
		case 5:
			c += ((u64)u.p8[4]) << 32;
		case 4:
			c += u.p32[0];
			break;
		case 3:
			c += ((u64)u.p8[2]) << 16;
		case 2:
			c += ((u64)u.p8[1]) << 8;
		case 1:
			c += (u64)u.p8[0];
			break;
		case 0:
			c += SC_CONST;
			d += SC_CONST;
	}
	short_end(a,b,c,d);
	*hash1 = a;
	*hash2 = b;
}

// do the whole hash in one call
void jelkins_spooky_hash128(
    const void *message,
    int length,
    u64 *hash1,
    u64 *hash2)
{
	u64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11;
	u64 buf[SC_NUMVARS];
	u64 *end;
	union
	{
		const u8 *p8;
		u64 *p64;
		int i;
	} u;
	int remainder;

	if (length < SC_BUFSIZE)
	{
		jelkins_spooky_hashshort(message, length, hash1, hash2);
		return;
	}

	h0=h3=h6=h9 =*hash1;
	h1=h4=h7=h10=*hash2;
	h2=h5=h8=h11=SC_CONST;

	u.p8 = (const u8 *)message;
	end = u.p64 + (length/SC_BLOCKSIZE)*SC_NUMVARS;

	// handle all whole sc_blockSize blocks of bytes
	if (ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0))
	{
		while (u.p64 < end)
		{ 
			mix(u.p64,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
			u.p64 += SC_NUMVARS;
		}
	}
	else
	{
		while (u.p64 < end)
		{
			memcpy(buf, u.p64, SC_BLOCKSIZE);
			mix(buf,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
			u.p64 += SC_NUMVARS;
		}
	}

	// handle the last partial block of sc_blockSize bytes
	remainder = (length - ((const u8 *)end-(const u8 *)message));
	memcpy(buf, end, remainder);
	memset(((u8 *)buf)+remainder, 0, SC_BLOCKSIZE-remainder);
	((u8 *)buf)[SC_BLOCKSIZE-1] = remainder;

	// do some final mixing
	end(buf,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
	*hash1 = h0;
	*hash2 = h1;
}

// init spooky state
void jelkins_spooky_init(struct jelkins_spooky *m, u64 seed1, u64 seed2)
{
	m->length = 0;
	m->remainder = 0;
	m->state[0] = seed1;
	m->state[1] = seed2;
}

// add a message fragment to the state
void jelkins_spooky_update(struct jelkins_spooky *m, const void *message,
			   int length)
{
	u64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11;
	int new_length = length + m->remainder;
	u8  remainder;
	union
	{
		const u8 *p8;
		u64 *p64;
		int i;
	} u;
	const u64 *end;

	// Is this message fragment too short?  If it is, stuff it away.
	if (new_length < SC_BUFSIZE)
	{
		memcpy(&((u8 *)m->data)[m->remainder], message, length);
		m->length = length + m->length;
		m->remainder = (u8)new_length;
		return;
	}

	// init the variables
	if (m->length < SC_BUFSIZE)
	{
		h0=h3=h6=h9 =m->state[0];
		h1=h4=h7=h10=m->state[1];
		h2=h5=h8=h11=SC_CONST;
	}
	else
	{
		h0 = m->state[0];
		h1 = m->state[1];
		h2 = m->state[2];
		h3 = m->state[3];
		h4 = m->state[4];
		h5 = m->state[5];
		h6 = m->state[6];
		h7 = m->state[7];
		h8 = m->state[8];
		h9 = m->state[9];
		h10 = m->state[10];
		h11 = m->state[11];
	}
	m->length = length + m->length;

	// if we've got anything stuffed away, use it now
	if (m->remainder)
	{
		u8 prefix = SC_BUFSIZE-m->remainder;
		memcpy(&(((u8 *)m->data)[m->remainder]), message, prefix);
		u.p64 = m->data;
		mix(u.p64,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
		mix(&u.p64[SC_NUMVARS],h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
		u.p8 = ((const u8 *)message) + prefix;
		length -= prefix;
	}
	else
	{
		u.p8 = (const u8 *)message;
	}

	// handle all whole blocks of SC_BLOCKSIZE bytes
	end = u.p64 + (length/SC_BLOCKSIZE)*SC_NUMVARS;
	remainder = (u8)(length-((const u8 *)end-u.p8));
	if (ALLOW_UNALIGNED_READS || (u.i & 0x7) == 0)
	{
		while (u.p64 < end)
		{ 
			mix(u.p64,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
			u.p64 += SC_NUMVARS;
		}
	}
	else
	{
		while (u.p64 < end)
		{ 
			memcpy(m->data, u.p8, SC_BLOCKSIZE);
			mix(m->data,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
			u.p64 += SC_NUMVARS;
		}
	}

	// stuff away the last few bytes
	m->remainder = remainder;
	memcpy(m->data, end, remainder);

	// stuff away the variables
	m->state[0] = h0;
	m->state[1] = h1;
	m->state[2] = h2;
	m->state[3] = h3;
	m->state[4] = h4;
	m->state[5] = h5;
	m->state[6] = h6;
	m->state[7] = h7;
	m->state[8] = h8;
	m->state[9] = h9;
	m->state[10] = h10;
	m->state[11] = h11;
}

// report the hash for the concatenation of all message fragments so far
void jelkins_spooky_final(struct jelkins_spooky *m, u64 *hash1, u64 *hash2)
{
	const u64 *data = (const u64 *)m->data;
	u8 remainder = m->remainder;
	u64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11;

	// init the variables
	if (m->length < SC_BUFSIZE)
	{
		*hash1 = m->state[0];
		*hash2 = m->state[1];
		jelkins_spooky_hashshort(m->data, m->length, hash1, hash2);
		return;
	}

	h0 = m->state[0];
	h1 = m->state[1];
	h2 = m->state[2];
	h3 = m->state[3];
	h4 = m->state[4];
	h5 = m->state[5];
	h6 = m->state[6];
	h7 = m->state[7];
	h8 = m->state[8];
	h9 = m->state[9];
	h10 = m->state[10];
	h11 = m->state[11];

	if (remainder >= SC_BLOCKSIZE)
	{
		// m->data can contain two blocks; handle any whole first block
		mix(data,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
		data += SC_NUMVARS;
		remainder -= SC_BLOCKSIZE;
	}

	// mix in the last partial block, and the length mod sc_blockSize
	memset(&((u8 *)data)[remainder], 0, (SC_BLOCKSIZE-remainder));

	((u8 *)data)[SC_BLOCKSIZE-1] = remainder;

	// do some final mixing
	end(data,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);

	*hash1 = h0;
	*hash2 = h1;
}


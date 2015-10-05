#ifndef _LINUX_AES_KHASH_H_
#define _LINUX_AES_KHASH_H_

#include <linux/types.h>

int aesni_khash_init(void);
int aesni_khash_exit(void);

void aesni_khash_hash(const unsigned char *name, unsigned int len, u8 *out);

#endif

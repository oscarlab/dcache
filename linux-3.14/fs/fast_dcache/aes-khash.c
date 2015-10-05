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

#include <linux/random.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include <crypto/aes.h>
#include <crypto/padlock.h>

#include <asm/i387.h>

#include "aes-khash.h"

struct crypto_aes_ctx ctx1 __attribute__ ((aligned(16)));
struct crypto_aes_ctx ctx2 __attribute__ ((aligned(16)));

asmlinkage int aesni_cbc_mac_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
                             unsigned int key_len);

int __init aesni_khash_init(void)
{
	char key_buf[32];

	get_random_bytes(key_buf, 32);
	//kernel_fpu_begin();
	aesni_cbc_mac_set_key(&ctx1, key_buf, 16);
	aesni_cbc_mac_set_key(&ctx2, key_buf + 16, 16);
	//kernel_fpu_end();

	return 0;
}

asmlinkage void aesni_cbc_mac(struct crypto_aes_ctx *ctx, u8 *out,
                              const u8 *in, unsigned int len);

void aesni_khash_hash(const unsigned char *name, unsigned int len, u8 *out)
{
	preempt_disable();
	aesni_cbc_mac(&ctx1, out, name, len);
	aesni_cbc_mac(&ctx2, out + 16, name, len);
	preempt_enable();
}

int __exit aesni_khash_exit(void)
{
	return 0;
}

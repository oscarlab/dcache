#include <linux/linkage.h>
#include <asm/inst.h>

.data
.align 16
SHIFT_MASK: .octa 0x0f0e0d0c0b0a09080706050403020100
ALL_F:      .octa 0xffffffffffffffffffffffffffffffff
ZERO:       .octa 0x00000000000000000000000000000000
.text

#define KEYP  %rdi
#define OUTP  %rsi
#define INP   %rdx
#define LEN   %rcx
#define KLEN  %r9d
#define T1    %r10
#define TKEYP T1

#define OUTP  %rsi
#define UKEYP OUTP
#define AREG  %rax

#define STATE %xmm0
#define IN    %xmm1
#define KEY   %xmm2

.align 4
_key_cbc_mac_expansion_128:
_key_cbc_mac_expansion_256a:
	pshufd $0b11111111, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0
	movaps %xmm0, (TKEYP)
	add $0x10, TKEYP
	ret
ENDPROC(_key_cbc_mac_expansion_128)
ENDPROC(_key_cbc_mac_expansion_256a)

.align 4
_key_cbc_mac_expansion_192a:
	pshufd $0b01010101, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0

	movaps %xmm2, %xmm5
	movaps %xmm2, %xmm6
	pslldq $4, %xmm5
	pshufd $0b11111111, %xmm0, %xmm3
	pxor %xmm3, %xmm2
	pxor %xmm5, %xmm2

	movaps %xmm0, %xmm1
	shufps $0b01000100, %xmm0, %xmm6
	movaps %xmm6, (TKEYP)
	shufps $0b01001110, %xmm2, %xmm1
	movaps %xmm1, 0x10(TKEYP)
	add $0x20, TKEYP
	ret
ENDPROC(_key_cbc_mac_expansion_192a)

.align 4
_key_cbc_mac_expansion_192b:
	pshufd $0b01010101, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0

	movaps %xmm2, %xmm5
	pslldq $4, %xmm5
	pshufd $0b11111111, %xmm0, %xmm3
	pxor %xmm3, %xmm2
	pxor %xmm5, %xmm2

	movaps %xmm0, (TKEYP)
	add $0x10, TKEYP
	ret
ENDPROC(_key_cbc_mac_expansion_192b)

.align 4
_key_cbc_mac_expansion_256b:
	pshufd $0b10101010, %xmm1, %xmm1
	shufps $0b00010000, %xmm2, %xmm4
	pxor %xmm4, %xmm2
	shufps $0b10001100, %xmm2, %xmm4
	pxor %xmm4, %xmm2
	pxor %xmm1, %xmm2
	movaps %xmm2, (TKEYP)
	add $0x10, TKEYP
	ret
ENDPROC(_key_cbc_mac_expansion_256b)

/*
 * int aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
 *                   unsigned int key_len)
 */
ENTRY(aesni_cbc_mac_set_key)
	movups (UKEYP), %xmm0		# user key (first 16 bytes)
	movaps %xmm0, (KEYP)
	lea 0x10(KEYP), TKEYP		# key addr
	movl %edx, 480(KEYP)
	pxor %xmm4, %xmm4		# xmm4 is assumed 0 in _key_cbc_mac_expansion_x
	cmp $24, %dl
	jb .Lenc_key128
	je .Lenc_key192
	movups 0x10(UKEYP), %xmm2	# other user key
	movaps %xmm2, (TKEYP)
	add $0x10, TKEYP
	AESKEYGENASSIST 0x1 %xmm2 %xmm1		# round 1
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x1 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x2 %xmm2 %xmm1		# round 2
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x2 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x4 %xmm2 %xmm1		# round 3
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x4 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x8 %xmm2 %xmm1		# round 4
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x8 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x10 %xmm2 %xmm1	# round 5
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x10 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x20 %xmm2 %xmm1	# round 6
	call _key_cbc_mac_expansion_256a
	AESKEYGENASSIST 0x20 %xmm0 %xmm1
	call _key_cbc_mac_expansion_256b
	AESKEYGENASSIST 0x40 %xmm2 %xmm1	# round 7
	call _key_cbc_mac_expansion_256a
	jmp .Ldec_key
.Lenc_key192:
	movq 0x10(UKEYP), %xmm2		# other user key
	AESKEYGENASSIST 0x1 %xmm2 %xmm1		# round 1
	call _key_cbc_mac_expansion_192a
	AESKEYGENASSIST 0x2 %xmm2 %xmm1		# round 2
	call _key_cbc_mac_expansion_192b
	AESKEYGENASSIST 0x4 %xmm2 %xmm1		# round 3
	call _key_cbc_mac_expansion_192a
	AESKEYGENASSIST 0x8 %xmm2 %xmm1		# round 4
	call _key_cbc_mac_expansion_192b
	AESKEYGENASSIST 0x10 %xmm2 %xmm1	# round 5
	call _key_cbc_mac_expansion_192a
	AESKEYGENASSIST 0x20 %xmm2 %xmm1	# round 6
	call _key_cbc_mac_expansion_192b
	AESKEYGENASSIST 0x40 %xmm2 %xmm1	# round 7
	call _key_cbc_mac_expansion_192a
	AESKEYGENASSIST 0x80 %xmm2 %xmm1	# round 8
	call _key_cbc_mac_expansion_192b
	jmp .Ldec_key
.Lenc_key128:
	AESKEYGENASSIST 0x1 %xmm0 %xmm1		# round 1
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x2 %xmm0 %xmm1		# round 2
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x4 %xmm0 %xmm1		# round 3
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x8 %xmm0 %xmm1		# round 4
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x10 %xmm0 %xmm1	# round 5
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x20 %xmm0 %xmm1	# round 6
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x40 %xmm0 %xmm1	# round 7
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x80 %xmm0 %xmm1	# round 8
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x1b %xmm0 %xmm1	# round 9
	call _key_cbc_mac_expansion_128
	AESKEYGENASSIST 0x36 %xmm0 %xmm1	# round 10
	call _key_cbc_mac_expansion_128
.Ldec_key:
	sub $0x10, TKEYP
	movaps (KEYP), %xmm0
	movaps (TKEYP), %xmm1
	movaps %xmm0, 240(TKEYP)
	movaps %xmm1, 240(KEYP)
	add $0x10, KEYP
	lea 240-16(TKEYP), UKEYP
.align 4
.Ldec_key_loop:
	movaps (KEYP), %xmm0
	AESIMC %xmm0 %xmm1
	movaps %xmm1, (UKEYP)
	add $0x10, KEYP
	sub $0x10, UKEYP
	cmp TKEYP, KEYP
	jb .Ldec_key_loop
	xor AREG, AREG
	ret
ENDPROC(aesni_cbc_mac_set_key)

.align 4
_aesni_enc1:
	movaps (KEYP), KEY		# key
	mov KEYP, TKEYP
	pxor KEY, STATE		# round 0
	add $0x30, TKEYP
	cmp $24, KLEN
	jb .Lenc128
	lea 0x20(TKEYP), TKEYP
	je .Lenc192
	add $0x20, TKEYP
	movaps -0x60(TKEYP), KEY
	AESENC KEY STATE
	movaps -0x50(TKEYP), KEY
	AESENC KEY STATE
.align 4
.Lenc192:
	movaps -0x40(TKEYP), KEY
	AESENC KEY STATE
	movaps -0x30(TKEYP), KEY
	AESENC KEY STATE
.align 4
.Lenc128:
	movaps -0x20(TKEYP), KEY
	AESENC KEY STATE
	movaps -0x10(TKEYP), KEY
	AESENC KEY STATE
	movaps (TKEYP), KEY
	AESENC KEY STATE
	movaps 0x10(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x20(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x30(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x40(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x50(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x60(TKEYP), KEY
	AESENC KEY STATE
	movaps 0x70(TKEYP), KEY
	AESENCLAST KEY STATE
	ret
ENDPROC(_aesni_enc1)

/*
 * void aesni_cbc_mac(struct crypto_aes_ctx *ctx, const u8 *dst, u8 *src,
 *                    unsigned int len)
 */
ENTRY(aesni_cbc_mac)
	push %r9
	push %r10
	sub $48, %rsp
	movups %xmm0, (%rsp)
	movups %xmm1, 16(%rsp)
	movups %xmm2, 32(%rsp)

	mov 480(KEYP), KLEN
	vmovd %ecx, STATE # put length to the first 4 bytes
	cmp $12, LEN
	jae .Lcbc_mac_ae12
	mov INP, T1 # length < 12
	and $0xfff, T1
	cmp $0xff0, T1
	jbe .Lcbc_mac_b12_normal
	sub $16, INP
	add LEN, INP
	movups (INP), IN
	lea ALL_F(%rip), T1
	sub LEN, T1
	movups (T1), KEY
	pshufb KEY, IN
	pslldq $4, IN
	por IN, STATE
	call _aesni_enc1
	jmp .Lcbc_mac_ret
.align 4
.Lcbc_mac_b12_normal:
	movups (INP), IN
	pslldq $4, IN 
	lea ALL_F+12(%rip), T1
	sub LEN, T1
	movups (T1), KEY
	pand KEY, IN
	por IN, STATE
	call _aesni_enc1
	jmp .Lcbc_mac_ret
.align 4
.Lcbc_mac_ae12:
	cmp $16, LEN
	jae .Lcbc_mac_normal
	mov INP, T1
	and $0xfff, T1
	cmp $0xff0, T1
	jbe .Lcbc_mac_normal
	sub $4, INP # 12 <= length < 16
	movups (INP), IN
	psrldq $4, IN
	pslldq $4, IN
	por IN, STATE
	call _aesni_enc1
	sub $12, LEN
	add $16, INP
	jmp .Lcbc_mac_remain
.align 4
.Lcbc_mac_normal:
	movups (INP), IN
	pslldq $4, IN
	por IN, STATE
	call _aesni_enc1
	sub $12, LEN
	add $12, INP
	cmp $16, LEN
	jb .Lcbc_mac_remain
.align 4
.Lcbc_mac_loop:
	movups (INP), IN
	pxor IN, STATE
	call _aesni_enc1
	sub $16, LEN
	add $16, INP
	cmp $16, LEN
	jae .Lcbc_mac_loop
.align 4
.Lcbc_mac_remain:
	cmp $0, LEN
	je .Lcbc_mac_ret
	mov INP, T1
	and $0xfff, T1
	cmp $0xff0, T1
	jbe .Lcbc_mac_remain_normal
	sub $16, INP
	add LEN, INP
	movups (INP), IN
	lea ALL_F(%rip), T1
	sub LEN, T1
	movups (T1), KEY
	pshufb KEY, IN
	pxor IN, STATE
	call _aesni_enc1
	jmp .Lcbc_mac_ret
.align 4
.Lcbc_mac_remain_normal:
	movups (INP), IN
	lea ALL_F+16(%rip), T1
	sub LEN, T1
	movups (T1), KEY
	pand KEY, IN
	pxor IN, STATE
	call _aesni_enc1
.align 4
.Lcbc_mac_ret:
	movups STATE, (OUTP)

	movups (%rsp), %xmm0
	movups 16(%rsp), %xmm1
	movups 32(%rsp), %xmm2
	add $48, %rsp
	pop %r10
	pop %r9
	ret
ENDPROC(aesni_cbc_mac)

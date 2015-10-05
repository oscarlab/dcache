#include <linux/linkage.h>
#include <asm/inst.h>

.macro CALGFSTEP YMMRES, KEYHI, KEYLO, MSG, XMM1, YMM1, YMM2, YMM3

	// YMM1 = MSG
	vpxor \XMM1, \XMM1, \XMM1
	vpinsrq $0, \MSG, \XMM1, \XMM1
	vpbroadcastd \XMM1, \YMM1

	// YMM2 = KEYHI
	vmovdqa (\KEYHI), \YMM2

	// YMM3 = lo(KEYHI) * lo(MSG)
	vpmuludq \YMM1, \YMM2, \YMM3

	// YMM1 = hi(KEYHI) * lo(MSG)
	vpsrlq $32, \YMM2, \YMM2
	vpmuludq \YMM1, \YMM2, \YMM1

	// YMM2 = lo2hi(lo(YMM1))
	vpsllq $32, \YMM1, \YMM2

	// YMM3 += YMM2
	vpaddq \YMM3, \YMM2, \YMM3

	// YMM2 = YMM1 = YMM1[0], YMM1[0], YMM[1], YMM[2]
	vpermq $0x90, \YMM1, \YMM2

	// YMM2[0] = XMM1[0] = KEYLO * MSG
	imul \MSG, \KEYLO
	vextracti128 $0, \YMM2, \XMM1
	vpinsrq $0, \KEYLO, \XMM1, \XMM1
	vinserti128 $0, \XMM1, \YMM2, \YMM2

	// YMM2 = hi(YMM2)
	vpsrlq $32, \YMM2, \YMM2

	// YMM3 += YMM2
	vpaddq \YMM3, \YMM2, \YMM3

	// YMMRES ^= YMM3
	vpxor \YMMRES, \YMM3, \YMMRES

.endm

##########################################################################
# unsigned int	mhash_hash_avx2
#		(void *name,		# RDI
#		unsigned int len,	# ESI
#		u64 *mptr,		# RDX
#		u64 *rpte,		# RCX
#		unsigned int state)	# r8d
##########################################################################
ENTRY(mhash_hash_avx2)

	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx

	mov	%r8d, %eax		# eax = state
	cmp	$0, %eax
	jne	_T_1
	vmovdqa	(%rdx), %ymm0		# ymm0 = mptr[0]
	jmp	_T_2

_T_1:
	vmovdqa	(%rcx), %ymm0		# ymm0 = current hash

_T_2:
	mov	%eax, %r12d		# r12 = &hi[state + 1]
	add	$1, %r12
	shl	$6, %r12
	add	%rdx, %r12

	mov	%rdi, %r13		# r13 = name
	mov	%esi, %r14d
	shr	$2, %r14d		# r14 = len / 4
	jmp	_T_4

_T_3:
	mov	(%r13), %ebx		# ebx = (name)
	mov	32(%r12), %r15d		# r15d = lo[state]

	CALGFSTEP %ymm0, %r12, %r15, %rbx, %xmm1, %ymm1, %ymm2, %ymm3

	add	$0x40, %r12
	add	$4, %r13
	sub	$1, %r14d
	add	$1, %eax

_T_4:
	test	%r14d, %r14d
	jne	_T_3

	mov	%esi, %r14d
	and	$3, %r14d		# r14 (rem) = len % 4
	cmp	$0, %r14d
	je	_T_5

	mov	(%r13), %ebx		# ebx = (name)
	mov	32(%r12), %r15d		# r15d = lo[state]

	mov	%rcx, %r13
	mov	%r14d, %ecx		# r13 = 1 << rem * 8 - 1
	shl	$3, %ecx
	mov	$1, %r14d
	shl	%cl, %r14d
	sub	$1, %r14d
	and	%r14d, %ebx		# ebx = (name) & r13d
	mov	%r13, %rcx

	CALGFSTEP %ymm0, %r12, %r15, %rbx, %xmm1, %ymm1, %ymm2, %ymm3

	add	$1, %eax

_T_5:
	vmovdqa	%ymm0, (%rcx)

	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12

	ret

ENDPROC(mhash_hash_avx2)

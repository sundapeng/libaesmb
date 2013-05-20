 ;
 ; Licensed to the Apache Software Foundation (ASF) under one
 ; or more contributor license agreements.  See the NOTICE file
 ; distributed with this work for additional information
 ; regarding copyright ownership.  The ASF licenses this file
 ; to you under the Apache License, Version 2.0 (the
 ; "License"); you may not use this file except in compliance
 ; with the License.  You may obtain a copy of the License at
 ;
 ;     http://www.apache.org/licenses/LICENSE-2.0
 ;
 ; Unless required by applicable law or agreed to in writing, software
 ; distributed under the License is distributed on an "AS IS" BASIS,
 ; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ; See the License for the specific language governing permissions and
 ; limitations under the License.
 ;

;
; Example YASM command lines:
; Windows:  yasm -Xvc -f x64 -rnasm -pnasm -o aes_cbc_dec_by8_sse.obj -g cv8 aes_cbc_dec_by8_sse.asm
; Linux:    yasm -f x64 -f elf64 -X gnu -g dwarf2 -D __linux__ -o aes_cbc_dec_by8_sse.o aes_cbc_dec_by8_sse.asm
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;

; routines to do AES128/192/256 CBC decrypt "by8"

%define CONCAT(a,b) a %+ b

struc sAesData
.in_block:	resq	1	; UINT8 *in_block
.out_block:	resq	1	; UINT8 *out_block
.expanded_key:	resq	1	; UINT8 *expanded_key
.iv:		resq	1	; UINT8 *iv
.num_blocks:	resd	1	; UINT32 num_blocks
endstruc

; void iDec128_CBC_by8(sAesData *data);
; void iDec192_CBC_by8(sAesData *data);
; void iDec256_CBC_by8(sAesData *data);

; Assume data is unaligned
%define MOVDQ movdqu

%define xdata0	xmm0
%define xdata1	xmm1
%define xdata2	xmm2
%define xdata3	xmm3
%define xdata4	xmm4
%define xdata5	xmm5
%define xdata6	xmm6
%define xdata7	xmm7
%define xIV  	xmm8
%define xkey0 	xmm9
%define xkey2 	xmm10
%define xkey4 	xmm11
%define xkey6 	xmm12
%define xkey8 	xmm13
%define xkeyA	xmm14
%define xkeyB	xmm15

%define xkeytmp1 xdata0
%define xkeytmp3 xdata1
%define xkeytmp5 xdata2
%define xkeytmp7 xdata3
%define xkeytmp9 xdata4
%define xkeytmp11 xdata5
%define xkeytmp12 xdata6
%define xkeytmp13 xdata7
%define xkeytmp14 xkeyA

%ifdef WINABI
%define ARG1	rcx
%else
%define ARG1	rdi
%endif
%define p_in	rdx
%define p_out	r8
%define p_keys	r9
%define p_IV	ARG1
%define num_blks eax

%define tmp	r10

struc STACK_FRAME
.keys		resdq	15
%ifdef WINABI
.xmm_save:	resdq	10
%endif
		resq 1		; for alignment
endstruc

; rounds: aes128 -> 10, aes192 -> 12, aes256 ->14
%define AES128 10
%define AES192 12
%define AES256 14


%macro do_aes 2
%define %%rounds %1
%define %%by   %2

  %assign i 0
  %rep %%by
	MOVDQ	CONCAT(xdata,i), [p_in  + i*16]
  %assign i (i+1)
  %endrep

	movdqa	xkeyA, [p_keys + (%%rounds-1)*16]

  %assign i 0
  %rep %%by
	pxor	CONCAT(xdata,i), xkey0		; round 0
  %assign i (i+1)
  %endrep

	add	p_in, 16*%%by

	
%assign r 3
%rep 4
  %assign rm1 (r-1)

  %assign i 0
  %rep %%by
	aesdec	CONCAT(xdata,i), xkeyA		; round r-2
  %assign i (i+1)
  %endrep

	movdqa	xkeyA, [p_keys + (%%rounds - r)*16]

  %assign i 0
  %rep %%by
	aesdec	CONCAT(xdata,i), CONCAT(xkey, rm1)	; round r-1
  %assign i (i+1)
  %endrep

%assign r (r+2)
%endrep

	;; completed up to round 8, key 9 loaded into xkeyA, r == 11

;; Do the following twice for aes256, once for aes192, and not for aes128
%rep (%%rounds - 10)/2

	movdqa	xkeyB, [p_keys + (%%rounds - (r-1))*16]

  %assign i 0
  %rep %%by
	aesdec	CONCAT(xdata,i), xkeyA		; round r-2
  %assign i (i+1)
  %endrep

	movdqa	xkeyA, [p_keys + (%%rounds - (r))*16]

  %assign i 0
  %rep %%by
	aesdec	CONCAT(xdata,i), xkeyB		; round r-1
  %assign i (i+1)
  %endrep

%assign r (r+2)
%endrep

%if (%%rounds != 10)
	movdqa	xkeyB, [p_keys + (%%rounds - (r-1))*16]
%endif

  %assign i 0
  %rep %%by
	aesdec	CONCAT(xdata,i), xkeyA		; round 9
  %assign i (i+1)
  %endrep

  %assign i 0
  %rep %%by
	aesdeclast	CONCAT(xdata,i), xkeyB		; round 10
  %assign i (i+1)
  %endrep

	pxor	xdata0, xIV
%assign i 1
%rep (%%by - 1)
	MOVDQ	xIV, [p_in  + (i-1)*16 - 16*%%by]
	pxor	CONCAT(xdata,i), xIV
%assign i (i+1)
%endrep
	MOVDQ	xIV, [p_in  + (i-1)*16 - 16*%%by]

%assign i 0
%rep %%by
	MOVDQ	[p_out  + i*16], CONCAT(xdata,i)
%assign i (i+1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


%macro AES_CBC_DEC_BY8 1
%define %%rounds %1

	sub	rsp, STACK_FRAME_size
%ifdef WINABI
	movdqa	[rsp + STACK_FRAME.xmm_save + 0*16], xmm6
	movdqa	[rsp + STACK_FRAME.xmm_save + 1*16], xmm7
	movdqa	[rsp + STACK_FRAME.xmm_save + 2*16], xmm8
	movdqa	[rsp + STACK_FRAME.xmm_save + 3*16], xmm9
	movdqa	[rsp + STACK_FRAME.xmm_save + 4*16], xmm10
	movdqa	[rsp + STACK_FRAME.xmm_save + 5*16], xmm11
	movdqa	[rsp + STACK_FRAME.xmm_save + 6*16], xmm12
	movdqa	[rsp + STACK_FRAME.xmm_save + 7*16], xmm13
	movdqa	[rsp + STACK_FRAME.xmm_save + 8*16], xmm14
	movdqa	[rsp + STACK_FRAME.xmm_save + 9*16], xmm15
%endif

	mov	p_in,     [ARG1 + sAesData.in_block]
	mov	p_out,    [ARG1 + sAesData.out_block]
	mov	p_keys,   [ARG1 + sAesData.expanded_key]
	mov	num_blks, [ARG1 + sAesData.num_blocks]
	mov	p_IV,     [ARG1 + sAesData.iv] ; clobbers ARG1

	movdqu	xIV, [p_IV]

	;; check align keys
	test	p_keys, 0xf
	jz	.skip_align

	;; do align keys
	movdqu	xkey0,    [p_keys + 16*(%%rounds-0)]
	movdqu	xkeytmp1, [p_keys + 16*(%%rounds-1)]
	movdqu	xkey2,    [p_keys + 16*(%%rounds-2)]
	movdqu	xkeytmp3, [p_keys + 16*(%%rounds-3)]
	movdqu	xkey4,    [p_keys + 16*(%%rounds-4)]
	movdqu	xkeytmp5, [p_keys + 16*(%%rounds-5)]
	movdqu	xkey6,    [p_keys + 16*(%%rounds-6)]
	movdqu	xkeytmp7, [p_keys + 16*(%%rounds-7)]
	movdqu	xkey8,    [p_keys + 16*(%%rounds-8)]
	movdqu	xkeytmp9, [p_keys + 16*(%%rounds-9)]
	movdqu	xkeyB,    [p_keys + 16*(%%rounds-10)]
%if (%%rounds > 10)
	movdqu	xkeytmp11,[p_keys + 16*(%%rounds-11)]
	movdqu	xkeytmp12,[p_keys + 16*(%%rounds-12)]
%endif
%if (%%rounds > 12)
	movdqu	xkeytmp13,[p_keys + 16*(%%rounds-13)]
	movdqu	xkeytmp14,[p_keys + 16*(%%rounds-14)]
%endif
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-1)], xkeytmp1
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-3)], xkeytmp3
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-5)], xkeytmp5
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-7)], xkeytmp7
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-9)], xkeytmp9
%if (%%rounds > 10)
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-10)], xkeyB
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-11)], xkeytmp11
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-12)], xkeytmp12
%endif
%if (%%rounds > 12)
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-13)], xkeytmp13
	movdqa	[rsp + STACK_FRAME.keys + 16*(%%rounds-14)], xkeytmp14
%endif

	lea	p_keys, [rsp + STACK_FRAME.keys]

	jmp .common

.skip_align
	movdqa	xkey0,    [p_keys + 16*(%%rounds-0)]
	movdqa	xkey2,    [p_keys + 16*(%%rounds-2)]
	movdqa	xkey4,    [p_keys + 16*(%%rounds-4)]
	movdqa	xkey6,    [p_keys + 16*(%%rounds-6)]
	movdqa	xkey8,    [p_keys + 16*(%%rounds-8)]
%if (%%rounds == 10)
	movdqa	xkeyB,    [p_keys + 16*(%%rounds-10)]
%endif

.common
	sub	num_blks, 8
	jl	.not8

align 16
.loop
	do_aes	%%rounds, 8
	add	p_out, 8*16
	sub	num_blks, 8
	jge	.loop

	; fewer than 8 remain:
	; num_blks = -1  =>  7 remaining
	;            -8  =>  0 remaining

.not8
	test	num_blks, 4
	jz	.not4
	do_aes	%%rounds, 4
	add	p_out, 4*16

.not4
	test	num_blks, 2
	jz	.not2
	do_aes	%%rounds, 2
	add	p_out, 2*16

.not2
	test	num_blks, 1
	jz	.return
	do_aes	%%rounds, 1

.return
	movdqu	[p_IV], xIV

%ifdef WINABI
	movdqa	xmm6, [rsp + STACK_FRAME.xmm_save + 0*16]
	movdqa	xmm7, [rsp + STACK_FRAME.xmm_save + 1*16]
	movdqa	xmm8, [rsp + STACK_FRAME.xmm_save + 2*16]
	movdqa	xmm9, [rsp + STACK_FRAME.xmm_save + 3*16]
	movdqa	xmm10, [rsp + STACK_FRAME.xmm_save + 4*16]
	movdqa	xmm11, [rsp + STACK_FRAME.xmm_save + 5*16]
	movdqa	xmm12, [rsp + STACK_FRAME.xmm_save + 6*16]
	movdqa	xmm13, [rsp + STACK_FRAME.xmm_save + 7*16]
	movdqa	xmm14, [rsp + STACK_FRAME.xmm_save + 8*16]
	movdqa	xmm15, [rsp + STACK_FRAME.xmm_save + 9*16]
%endif
	add	rsp, STACK_FRAME_size
	ret
%endm


global iDec128_CBC_by8
iDec128_CBC_by8:
	AES_CBC_DEC_BY8 AES128

global iDec192_CBC_by8
iDec192_CBC_by8:
	AES_CBC_DEC_BY8 AES192

global iDec256_CBC_by8
iDec256_CBC_by8:
	AES_CBC_DEC_BY8 AES256

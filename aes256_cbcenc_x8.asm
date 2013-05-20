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


; Routines to do simple AES CBC Enc
; "Simple" means same key for all streams, same length for all streams

; typedef struct _sAesData_x8 {
;     unsigned char *inbuf[8];
;     unsigned char *outbuf[8];
;     unsigned char *keysched;
;     unsigned char *iv[8];
;     UINT64 numblocks;
; } sAesData_x8;
; 
; // The same key is applied to all streams
; void aes_cbc_enc_128_x8(sAesData_x8 *args);
; void aes_cbc_enc_192_x8(sAesData_x8 *args);
; void aes_cbc_enc_256_x8(sAesData_x8 *args);

IN_SIZE		equ	8*8
OUT_SIZE	equ	8*8
KEYS_SIZE	equ	1*8
IV_SIZE		equ	8*8
LEN_SIZE	equ	8

IN_OFFSET	equ	0
OUT_OFFSET	equ	IN_OFFSET + IN_SIZE
KEYS_OFFSET	equ	OUT_OFFSET + OUT_SIZE
IV_OFFSET	equ	KEYS_OFFSET + KEYS_SIZE
LEN_OFFSET	equ	IV_OFFSET + IV_SIZE

;; stack size needs to be an odd multiple of 8 for alignment
%ifdef WINABI
XMM_SAVE_SIZE	equ	16*10
GPR_SAVE_SIZE	equ	8*7
%else
XMM_SAVE_SIZE	equ	0
GPR_SAVE_SIZE	equ	8*5
%endif
STACK_SIZE	equ	XMM_SAVE_SIZE + GPR_SAVE_SIZE

%define GPR_SAVE_AREA	rsp + XMM_SAVE_SIZE

;; assume buffers not aligned 
%define	MOVDQ movdqu
%macro pxor2 2
	MOVDQ	XTMP, %2
	pxor	%1, XTMP
%endm

;; assume keys are not aligned
%define MOVDQ_KEYS movdqu

%ifdef WINABI
%define ARG	rcx
%define LEN	rdx
%define TMP1	rsi
%define TMP2	rdi
%else
%define ARG	rdi
%define LEN	rsi
%define TMP1	rcx
%define TMP2	rdx
%endif

%define IDX	rax
%define KEYS	rbx

%define IN0	r8
%define OUT0	r9
%define IV0	OUT0

%define IN2	r10
%define OUT2	r11
%define IV2	OUT2

%define IN4	r12
%define OUT4	r13
%define IV4	OUT4

%define IN6	r14
%define OUT6	r15
%define IV6	OUT6


%define XDATA0		xmm0
%define XDATA1		xmm1
%define XDATA2		xmm2
%define XDATA3		xmm3
%define XDATA4		xmm4
%define XDATA5		xmm5
%define XDATA6		xmm6
%define XDATA7		xmm7

;%define XKEY0		xmm
%define XKEY1		xmm8
;%define XKEY2		xmm
%define XKEY3		xmm9
;%define XKEY4		xmm
%define XKEY5		xmm10
;%define XKEY6		xmm
%define XKEY7		xmm11
;%define XKEY8		xmm
%define XKEY9		xmm12
;%define XKEY10		xmm
%define XKEY11		xmm13
;%define XKEY12		xmm
%define XKEY13		xmm14
;%define XKEY14		xmm

%define XTMP		xmm15

global aes_cbc_enc_256_x8
aes_cbc_enc_256_x8:

	mov	LEN, [ARG + LEN_OFFSET]
	sub	rsp, STACK_SIZE
%ifdef WINABI
	movdqa	[rsp + 16*0], xmm6
	movdqa	[rsp + 16*1], xmm7
	movdqa	[rsp + 16*2], xmm8
	movdqa	[rsp + 16*3], xmm9
	movdqa	[rsp + 16*4], xmm10
	movdqa	[rsp + 16*5], xmm11
	movdqa	[rsp + 16*6], xmm12
	movdqa	[rsp + 16*7], xmm13
	movdqa	[rsp + 16*8], xmm14
	movdqa	[rsp + 16*9], xmm15
%endif
	mov	[GPR_SAVE_AREA + 8*0], rbx
	mov	[GPR_SAVE_AREA + 8*1], r12
	mov	[GPR_SAVE_AREA + 8*2], r13
	mov	[GPR_SAVE_AREA + 8*3], r14
	mov	[GPR_SAVE_AREA + 8*4], r15
%ifdef WINABI
	mov	[GPR_SAVE_AREA + 8*5], rsi
	mov	[GPR_SAVE_AREA + 8*6], rdi
%endif

	mov	IDX, 16
	shl	LEN, 4	;; LEN = LEN * 16
	;; LEN is now in terms of bytes
	jz	zero_len

	mov	IN0,	[ARG + IN_OFFSET + 8*0]
	mov	IN2,	[ARG + IN_OFFSET + 8*2]
	mov	IN4,	[ARG + IN_OFFSET + 8*4]
	mov	IN6,	[ARG + IN_OFFSET + 8*6]

	mov	IV0,	[ARG + IV_OFFSET + 8*0]
	mov	IV2,	[ARG + IV_OFFSET + 8*2]
	mov	IV4,	[ARG + IV_OFFSET + 8*4]
	mov	IV6,	[ARG + IV_OFFSET + 8*6]

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov	TMP1,	[ARG + IN_OFFSET + 8*1]
	mov	TMP2,	[ARG + IN_OFFSET + 8*3]
	MOVDQ		XDATA0, [IN0]		; load first block of plain text
	MOVDQ		XDATA1, [TMP1]		; load first block of plain text
	mov	TMP1,	[ARG + IN_OFFSET + 8*5]
	MOVDQ		XDATA2, [IN2]		; load first block of plain text
	MOVDQ		XDATA3, [TMP2]		; load first block of plain text
	mov	TMP2,	[ARG + IN_OFFSET + 8*7]
	MOVDQ		XDATA4, [IN4]		; load first block of plain text
	MOVDQ		XDATA5, [TMP1]		; load first block of plain text
	MOVDQ		XDATA6, [IN6]		; load first block of plain text
	MOVDQ		XDATA7, [TMP2]		; load first block of plain text

	mov		KEYS,	[ARG + KEYS_OFFSET]

	mov	TMP1,	[ARG + IV_OFFSET + 8*1]
	mov	TMP2,	[ARG + IV_OFFSET + 8*3]
	pxor2		XDATA0, [IV0]	; plaintext XOR IV	
	pxor2		XDATA1, [TMP1]	; plaintext XOR IV	
	mov	TMP1,	[ARG + IV_OFFSET + 8*5]
 	pxor2		XDATA2, [IV2]	; plaintext XOR IV	
	pxor2		XDATA3, [TMP2]	; plaintext XOR IV	
	mov	TMP2,	[ARG + IV_OFFSET + 8*7]
	pxor2		XDATA4, [IV4]	; plaintext XOR IV	
	pxor2		XDATA5, [TMP1]	; plaintext XOR IV	
	pxor2		XDATA6, [IV6]	; plaintext XOR IV	
	pxor2		XDATA7, [TMP2]	; plaintext XOR IV	

	MOVDQ_KEYS	XTMP, [KEYS + 16*0]

	mov		OUT0,	[ARG + OUT_OFFSET + 8*0]
	mov		OUT2,	[ARG + OUT_OFFSET + 8*2]
	mov		OUT4,	[ARG + OUT_OFFSET + 8*4]
	mov		OUT6,	[ARG + OUT_OFFSET + 8*6]

	MOVDQ_KEYS	XKEY1, [KEYS + 16*1]
	pxor		XDATA0, XTMP	; 0. ARK
	pxor		XDATA1, XTMP	; 0. ARK
	pxor		XDATA2, XTMP	; 0. ARK
	pxor		XDATA3, XTMP	; 0. ARK
	pxor		XDATA4, XTMP	; 0. ARK
	pxor		XDATA5, XTMP	; 0. ARK
	pxor		XDATA6, XTMP	; 0. ARK
	pxor		XDATA7, XTMP	; 0. ARK

	MOVDQ_KEYS	XTMP, [KEYS + 16*2]
	aesenc		XDATA0, XKEY1	; 1. ENC
	aesenc		XDATA1, XKEY1	; 1. ENC
	aesenc		XDATA2, XKEY1	; 1. ENC
	aesenc		XDATA3, XKEY1	; 1. ENC
	aesenc		XDATA4, XKEY1	; 1. ENC
	aesenc		XDATA5, XKEY1	; 1. ENC
	aesenc		XDATA6, XKEY1	; 1. ENC
	aesenc		XDATA7, XKEY1	; 1. ENC

	MOVDQ_KEYS	XKEY3, [KEYS + 16*3]
	aesenc		XDATA0, XTMP	; 2. ENC
	aesenc		XDATA1, XTMP	; 2. ENC
	aesenc		XDATA2, XTMP	; 2. ENC
	aesenc		XDATA3, XTMP	; 2. ENC
	aesenc		XDATA4, XTMP	; 2. ENC
	aesenc		XDATA5, XTMP	; 2. ENC
	aesenc		XDATA6, XTMP	; 2. ENC
	aesenc		XDATA7, XTMP	; 2. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*4]
	aesenc		XDATA0, XKEY3	; 3. ENC
	aesenc		XDATA1, XKEY3	; 3. ENC
	aesenc		XDATA2, XKEY3	; 3. ENC
	aesenc		XDATA3, XKEY3	; 3. ENC
	aesenc		XDATA4, XKEY3	; 3. ENC
	aesenc		XDATA5, XKEY3	; 3. ENC
	aesenc		XDATA6, XKEY3	; 3. ENC
	aesenc		XDATA7, XKEY3	; 3. ENC

	MOVDQ_KEYS	XKEY5, [KEYS + 16*5]
	aesenc		XDATA0, XTMP	; 4. ENC
	aesenc		XDATA1, XTMP	; 4. ENC
	aesenc		XDATA2, XTMP	; 4. ENC
	aesenc		XDATA3, XTMP	; 4. ENC
	aesenc		XDATA4, XTMP	; 4. ENC
	aesenc		XDATA5, XTMP	; 4. ENC
	aesenc		XDATA6, XTMP	; 4. ENC
	aesenc		XDATA7, XTMP	; 4. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*6]
	aesenc		XDATA0, XKEY5	; 5. ENC
	aesenc		XDATA1, XKEY5	; 5. ENC
	aesenc		XDATA2, XKEY5	; 5. ENC
	aesenc		XDATA3, XKEY5	; 5. ENC
	aesenc		XDATA4, XKEY5	; 5. ENC
	aesenc		XDATA5, XKEY5	; 5. ENC
	aesenc		XDATA6, XKEY5	; 5. ENC
	aesenc		XDATA7, XKEY5	; 5. ENC

	MOVDQ_KEYS	XKEY7, [KEYS + 16*7]
	aesenc		XDATA0, XTMP	; 6. ENC
	aesenc		XDATA1, XTMP	; 6. ENC
	aesenc		XDATA2, XTMP	; 6. ENC
	aesenc		XDATA3, XTMP	; 6. ENC
	aesenc		XDATA4, XTMP	; 6. ENC
	aesenc		XDATA5, XTMP	; 6. ENC
	aesenc		XDATA6, XTMP	; 6. ENC
	aesenc		XDATA7, XTMP	; 6. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*8]
	aesenc		XDATA0, XKEY7	; 7. ENC
	aesenc		XDATA1, XKEY7	; 7. ENC
	aesenc		XDATA2, XKEY7	; 7. ENC
	aesenc		XDATA3, XKEY7	; 7. ENC
	aesenc		XDATA4, XKEY7	; 7. ENC
	aesenc		XDATA5, XKEY7	; 7. ENC
	aesenc		XDATA6, XKEY7	; 7. ENC
	aesenc		XDATA7, XKEY7	; 7. ENC

	MOVDQ_KEYS	XKEY9, [KEYS + 16*9]
	aesenc		XDATA0, XTMP	; 8. ENC
	aesenc		XDATA1, XTMP	; 8. ENC
	aesenc		XDATA2, XTMP	; 8. ENC
	aesenc		XDATA3, XTMP	; 8. ENC
	aesenc		XDATA4, XTMP	; 8. ENC
	aesenc		XDATA5, XTMP	; 8. ENC
	aesenc		XDATA6, XTMP	; 8. ENC
	aesenc		XDATA7, XTMP	; 8. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*10]
	aesenc		XDATA0, XKEY9	; 9. ENC
	aesenc		XDATA1, XKEY9	; 9. ENC
	aesenc		XDATA2, XKEY9	; 9. ENC
	aesenc		XDATA3, XKEY9	; 9. ENC
	aesenc		XDATA4, XKEY9	; 9. ENC
	aesenc		XDATA5, XKEY9	; 9. ENC
	aesenc		XDATA6, XKEY9	; 9. ENC
	aesenc		XDATA7, XKEY9	; 9. ENC

	MOVDQ_KEYS	XKEY11, [KEYS + 16*11]
	aesenc		XDATA0, XTMP	; 10. ENC
	aesenc		XDATA1, XTMP	; 10. ENC
	aesenc		XDATA2, XTMP	; 10. ENC
	aesenc		XDATA3, XTMP	; 10. ENC
	aesenc		XDATA4, XTMP	; 10. ENC
	aesenc		XDATA5, XTMP	; 10. ENC
	aesenc		XDATA6, XTMP	; 10. ENC
	aesenc		XDATA7, XTMP	; 10. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*12]
	aesenc		XDATA0, XKEY11	; 11. ENC
	aesenc		XDATA1, XKEY11	; 11. ENC
	aesenc		XDATA2, XKEY11	; 11. ENC
	aesenc		XDATA3, XKEY11	; 11. ENC
	aesenc		XDATA4, XKEY11	; 11. ENC
	aesenc		XDATA5, XKEY11	; 11. ENC
	aesenc		XDATA6, XKEY11	; 11. ENC
	aesenc		XDATA7, XKEY11	; 11. ENC

	MOVDQ_KEYS	XKEY13, [KEYS + 16*13]
	aesenc		XDATA0, XTMP	; 12. ENC
	aesenc		XDATA1, XTMP	; 12. ENC
	aesenc		XDATA2, XTMP	; 12. ENC
	aesenc		XDATA3, XTMP	; 12. ENC
	aesenc		XDATA4, XTMP	; 12. ENC
	aesenc		XDATA5, XTMP	; 12. ENC
	aesenc		XDATA6, XTMP	; 12. ENC
	aesenc		XDATA7, XTMP	; 12. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*14]
	aesenc		XDATA0, XKEY13	; 13. ENC
	aesenc		XDATA1, XKEY13	; 13. ENC
	aesenc		XDATA2, XKEY13	; 13. ENC
	aesenc		XDATA3, XKEY13	; 13. ENC
	aesenc		XDATA4, XKEY13	; 13. ENC
	aesenc		XDATA5, XKEY13	; 13. ENC
	aesenc		XDATA6, XKEY13	; 13. ENC
	aesenc		XDATA7, XKEY13	; 13. ENC

	aesenclast	XDATA0, XTMP	; 14. ENC
	aesenclast	XDATA1, XTMP	; 14. ENC
	aesenclast	XDATA2, XTMP	; 14. ENC
	aesenclast	XDATA3, XTMP	; 14. ENC
	aesenclast	XDATA4, XTMP	; 14. ENC
	aesenclast	XDATA5, XTMP	; 14. ENC
	aesenclast	XDATA6, XTMP	; 14. ENC
	aesenclast	XDATA7, XTMP	; 14. ENC

	mov		TMP1,	[ARG + OUT_OFFSET + 8*1]
	mov		TMP2,	[ARG + OUT_OFFSET + 8*3]
	MOVDQ		[OUT0], XDATA0	; write back ciphertext
	MOVDQ		[TMP1], XDATA1	; write back ciphertext
	mov		TMP1,	[ARG + OUT_OFFSET + 8*5]
	MOVDQ		[OUT2], XDATA2	; write back ciphertext
	MOVDQ		[TMP2], XDATA3	; write back ciphertext
	mov		TMP2,	[ARG + OUT_OFFSET + 8*7]
	MOVDQ		[OUT4], XDATA4	; write back ciphertext
	MOVDQ		[TMP1], XDATA5	; write back ciphertext
	MOVDQ		[OUT6], XDATA6	; write back ciphertext
	MOVDQ		[TMP2], XDATA7	; write back ciphertext

	cmp		LEN, IDX
	je		done

main_loop:	
	mov	TMP1,	[ARG + IN_OFFSET + 8*1]
	mov	TMP2,	[ARG + IN_OFFSET + 8*3]
	pxor2		XDATA0, [IN0 + IDX]	; plaintext XOR IV
	pxor2		XDATA1, [TMP1 + IDX]	; plaintext XOR IV
	mov	TMP1,	[ARG + IN_OFFSET + 8*5]
	pxor2		XDATA2, [IN2 + IDX]	; plaintext XOR IV
	pxor2		XDATA3, [TMP2 + IDX]	; plaintext XOR IV
	mov	TMP2,	[ARG + IN_OFFSET + 8*7]
	pxor2		XDATA4, [IN4 + IDX]	; plaintext XOR IV
	pxor2		XDATA5, [TMP1 + IDX]	; plaintext XOR IV
	pxor2		XDATA6, [IN6 + IDX]	; plaintext XOR IV
	pxor2		XDATA7, [TMP2 + IDX]	; plaintext XOR IV

	MOVDQ_KEYS	XTMP, [KEYS + 16*0]

	pxor		XDATA0, XTMP 	; 0. ARK
	pxor		XDATA1, XTMP 	; 0. ARK
	pxor		XDATA2, XTMP 	; 0. ARK
	pxor		XDATA3, XTMP 	; 0. ARK
	pxor		XDATA4, XTMP 	; 0. ARK
	pxor		XDATA5, XTMP 	; 0. ARK
	pxor		XDATA6, XTMP 	; 0. ARK
	pxor		XDATA7, XTMP 	; 0. ARK

	MOVDQ_KEYS	XTMP, [KEYS + 16*2]
	aesenc		XDATA0, XKEY1	; 1. ENC
	aesenc		XDATA1, XKEY1	; 1. ENC
	aesenc		XDATA2, XKEY1	; 1. ENC
	aesenc		XDATA3, XKEY1	; 1. ENC
	aesenc		XDATA4, XKEY1	; 1. ENC
	aesenc		XDATA5, XKEY1	; 1. ENC
	aesenc		XDATA6, XKEY1	; 1. ENC
	aesenc		XDATA7, XKEY1	; 1. ENC

	aesenc		XDATA0, XTMP	; 2. ENC
	aesenc		XDATA1, XTMP	; 2. ENC
	aesenc		XDATA2, XTMP	; 2. ENC
	aesenc		XDATA3, XTMP	; 2. ENC
	aesenc		XDATA4, XTMP	; 2. ENC
	aesenc		XDATA5, XTMP	; 2. ENC
	aesenc		XDATA6, XTMP	; 2. ENC
	aesenc		XDATA7, XTMP	; 2. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*4]
	aesenc		XDATA0, XKEY3	; 3. ENC
	aesenc		XDATA1, XKEY3	; 3. ENC
	aesenc		XDATA2, XKEY3	; 3. ENC
	aesenc		XDATA3, XKEY3	; 3. ENC
	aesenc		XDATA4, XKEY3	; 3. ENC
	aesenc		XDATA5, XKEY3	; 3. ENC
	aesenc		XDATA6, XKEY3	; 3. ENC
	aesenc		XDATA7, XKEY3	; 3. ENC

	aesenc		XDATA0, XTMP	; 4. ENC
	aesenc		XDATA1, XTMP	; 4. ENC
	aesenc		XDATA2, XTMP	; 4. ENC
	aesenc		XDATA3, XTMP	; 4. ENC
	aesenc		XDATA4, XTMP	; 4. ENC
	aesenc		XDATA5, XTMP	; 4. ENC
	aesenc		XDATA6, XTMP	; 4. ENC
	aesenc		XDATA7, XTMP	; 4. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*6]
	aesenc		XDATA0, XKEY5	; 5. ENC
	aesenc		XDATA1, XKEY5	; 5. ENC
	aesenc		XDATA2, XKEY5	; 5. ENC
	aesenc		XDATA3, XKEY5	; 5. ENC
	aesenc		XDATA4, XKEY5	; 5. ENC
	aesenc		XDATA5, XKEY5	; 5. ENC
	aesenc		XDATA6, XKEY5	; 5. ENC
	aesenc		XDATA7, XKEY5	; 5. ENC

	aesenc		XDATA0, XTMP	; 6. ENC
	aesenc		XDATA1, XTMP	; 6. ENC
	aesenc		XDATA2, XTMP	; 6. ENC
	aesenc		XDATA3, XTMP	; 6. ENC
	aesenc		XDATA4, XTMP	; 6. ENC
	aesenc		XDATA5, XTMP	; 6. ENC
	aesenc		XDATA6, XTMP	; 6. ENC
	aesenc		XDATA7, XTMP	; 6. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*8]
	aesenc		XDATA0, XKEY7	; 7. ENC
	aesenc		XDATA1, XKEY7	; 7. ENC
	aesenc		XDATA2, XKEY7	; 7. ENC
	aesenc		XDATA3, XKEY7	; 7. ENC
	aesenc		XDATA4, XKEY7	; 7. ENC
	aesenc		XDATA5, XKEY7	; 7. ENC
	aesenc		XDATA6, XKEY7	; 7. ENC
	aesenc		XDATA7, XKEY7	; 7. ENC

	aesenc		XDATA0, XTMP	; 8. ENC
	aesenc		XDATA1, XTMP	; 8. ENC
	aesenc		XDATA2, XTMP	; 8. ENC
	aesenc		XDATA3, XTMP	; 8. ENC
	aesenc		XDATA4, XTMP	; 8. ENC
	aesenc		XDATA5, XTMP	; 8. ENC
	aesenc		XDATA6, XTMP	; 8. ENC
	aesenc		XDATA7, XTMP	; 8. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*10]
	aesenc		XDATA0, XKEY9	; 9. ENC
	aesenc		XDATA1, XKEY9	; 9. ENC
	aesenc		XDATA2, XKEY9	; 9. ENC
	aesenc		XDATA3, XKEY9	; 9. ENC
	aesenc		XDATA4, XKEY9	; 9. ENC
	aesenc		XDATA5, XKEY9	; 9. ENC
	aesenc		XDATA6, XKEY9	; 9. ENC
	aesenc		XDATA7, XKEY9	; 9. ENC

	aesenc		XDATA0, XTMP	; 10. ENC
	aesenc		XDATA1, XTMP	; 10. ENC
	aesenc		XDATA2, XTMP	; 10. ENC
	aesenc		XDATA3, XTMP	; 10. ENC
	aesenc		XDATA4, XTMP	; 10. ENC
	aesenc		XDATA5, XTMP	; 10. ENC
	aesenc		XDATA6, XTMP	; 10. ENC
	aesenc		XDATA7, XTMP	; 10. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*12]
	aesenc		XDATA0, XKEY11	; 11. ENC
	aesenc		XDATA1, XKEY11	; 11. ENC
	aesenc		XDATA2, XKEY11	; 11. ENC
	aesenc		XDATA3, XKEY11	; 11. ENC
	aesenc		XDATA4, XKEY11	; 11. ENC
	aesenc		XDATA5, XKEY11	; 11. ENC
	aesenc		XDATA6, XKEY11	; 11. ENC
	aesenc		XDATA7, XKEY11	; 11. ENC

	aesenc		XDATA0, XTMP	; 12. ENC
	aesenc		XDATA1, XTMP	; 12. ENC
	aesenc		XDATA2, XTMP	; 12. ENC
	aesenc		XDATA3, XTMP	; 12. ENC
	aesenc		XDATA4, XTMP	; 12. ENC
	aesenc		XDATA5, XTMP	; 12. ENC
	aesenc		XDATA6, XTMP	; 12. ENC
	aesenc		XDATA7, XTMP	; 12. ENC

	MOVDQ_KEYS	XTMP, [KEYS + 16*14]
	aesenc		XDATA0, XKEY13	; 13. ENC
	aesenc		XDATA1, XKEY13	; 13. ENC
	aesenc		XDATA2, XKEY13	; 13. ENC
	aesenc		XDATA3, XKEY13	; 13. ENC
	aesenc		XDATA4, XKEY13	; 13. ENC
	aesenc		XDATA5, XKEY13	; 13. ENC
	aesenc		XDATA6, XKEY13	; 13. ENC
	aesenc		XDATA7, XKEY13	; 13. ENC

	aesenclast	XDATA0, XTMP	; 14. ENC
	aesenclast	XDATA1, XTMP	; 14. ENC
	aesenclast	XDATA2, XTMP	; 14. ENC
	aesenclast	XDATA3, XTMP	; 14. ENC
	aesenclast	XDATA4, XTMP	; 14. ENC
	aesenclast	XDATA5, XTMP	; 14. ENC
	aesenclast	XDATA6, XTMP	; 14. ENC
	aesenclast	XDATA7, XTMP	; 14. ENC


	mov	TMP1,	[ARG + OUT_OFFSET + 8*1]
	mov	TMP2,	[ARG + OUT_OFFSET + 8*3]
	MOVDQ		[OUT0 + IDX], XDATA0	; write back ciphertext
	MOVDQ		[TMP1 + IDX], XDATA1	; write back ciphertext
	mov	TMP1,	[ARG + OUT_OFFSET + 8*5]
	MOVDQ		[OUT2 + IDX], XDATA2	; write back ciphertex
	MOVDQ		[TMP2 + IDX], XDATA3	; write back ciphertext
	mov	TMP2,	[ARG + OUT_OFFSET + 8*7]
	MOVDQ		[OUT4 + IDX], XDATA4	; write back ciphertex
	MOVDQ		[TMP1 + IDX], XDATA5	; write back ciphertext
	MOVDQ		[OUT6 + IDX], XDATA6	; write back ciphertex
	MOVDQ		[TMP2 + IDX], XDATA7	; write back ciphertext


	add	IDX, 16
	cmp	LEN, IDX
	jne	main_loop

done:
	;; update IV

	mov	IV0,	[ARG + IV_OFFSET + 8*0]
	mov	IV2,	[ARG + IV_OFFSET + 8*1]
	mov	IV4,	[ARG + IV_OFFSET + 8*2]
	mov	IV6,	[ARG + IV_OFFSET + 8*3]
	movdqu	[IV0], XDATA0
	movdqu	[IV2], XDATA1
	mov	IV0,	[ARG + IV_OFFSET + 8*4]
	mov	IV2,	[ARG + IV_OFFSET + 8*5]
	movdqu	[IV4], XDATA2
	movdqu	[IV6], XDATA3
	mov	IV4,	[ARG + IV_OFFSET + 8*6]
	mov	IV6,	[ARG + IV_OFFSET + 8*7]
	movdqu	[IV0], XDATA4
	movdqu	[IV2], XDATA5
	movdqu	[IV4], XDATA6
	movdqu	[IV6], XDATA7

zero_len:
%ifdef WINABI
	movdqa	xmm6,  [rsp + 16*0]
	movdqa	xmm7,  [rsp + 16*1]
	movdqa	xmm8,  [rsp + 16*2]
	movdqa	xmm9,  [rsp + 16*3]
	movdqa	xmm10, [rsp + 16*4]
	movdqa	xmm11, [rsp + 16*5]
	movdqa	xmm12, [rsp + 16*6]
	movdqa	xmm13, [rsp + 16*7]
	movdqa	xmm14, [rsp + 16*8]
	movdqa	xmm15, [rsp + 16*9]
%endif
	mov	rbx, [GPR_SAVE_AREA + 8*0]
	mov	r12, [GPR_SAVE_AREA + 8*1]
	mov	r13, [GPR_SAVE_AREA + 8*2]
	mov	r14, [GPR_SAVE_AREA + 8*3]
	mov	r15, [GPR_SAVE_AREA + 8*4]
%ifdef WINABI
	mov	rsi, [GPR_SAVE_AREA + 8*5]
	mov	rdi, [GPR_SAVE_AREA + 8*6]
%endif
	
	add	rsp, STACK_SIZE

	ret

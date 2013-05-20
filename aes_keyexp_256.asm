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

; Routine to do AES key expansion

;; assume keys are not aligned
%define MOVDQ_KEYS movdqu

; Uses the f() function of the aeskeygenassist result
%macro key_expansion_256_sse 0
	;; Assumes the xmm3 includes all zeros at this point. 
        pshufd	xmm2, xmm2, 11111111b        
        shufps	xmm3, xmm1, 00010000b        
        pxor	xmm1, xmm3        
        shufps	xmm3, xmm1, 10001100b
        pxor	xmm1, xmm3        
	pxor	xmm1, xmm2
%endmacro

; Uses the SubWord function of the aeskeygenassist result
%macro key_expansion_256_sse_2 0
	;; Assumes the xmm3 includes all zeros at this point. 
        pshufd	xmm2, xmm2, 10101010b
        shufps	xmm3, xmm4, 00010000b        
        pxor	xmm4, xmm3        
        shufps	xmm3, xmm4, 10001100b
        pxor	xmm4, xmm3        
	pxor	xmm4, xmm2		
%endmacro

%ifdef WINABI
%define KEY		rcx
%define EXP_KEYS	rdx
%else
%define KEY		rdi
%define EXP_KEYS	rsi
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; void aes_keyexp_256_enc(UINT128 *key,
;                         UINT128 *enc_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for encrypt
;
global aes_keyexp_256_enc :function
aes_keyexp_256_enc:
        movdqu	xmm1, [KEY]			; loading the AES key
	MOVDQ_KEYS	[EXP_KEYS + 16*0], xmm1
        
        movdqu	xmm4, [KEY+16]			; loading the AES key
	MOVDQ_KEYS	[EXP_KEYS + 16*1], xmm4
                        
        pxor xmm3, xmm3				; Required for the key_expansion.

        aeskeygenassist xmm2, xmm4, 0x1		; Generating round key 2 
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*2], xmm1
        
        aeskeygenassist xmm2, xmm1, 0x1		; Generating round key 3
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*3], xmm4

        aeskeygenassist xmm2, xmm4, 0x2		; Generating round key 4 
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*4], xmm1
        
        aeskeygenassist xmm2, xmm1, 0x2		; Generating round key 5
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*5], xmm4

        aeskeygenassist xmm2, xmm4, 0x4		; Generating round key 6 
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*6], xmm1
		
        aeskeygenassist xmm2, xmm1, 0x4		; Generating round key 7
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*7], xmm4

        aeskeygenassist xmm2, xmm4, 0x8		; Generating round key 8 
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*8], xmm1
		
        aeskeygenassist xmm2, xmm1, 0x8		; Generating round key 9
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*9], xmm4

        aeskeygenassist xmm2, xmm4, 0x10	; Generating round key 10
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*10], xmm1
		
        aeskeygenassist xmm2, xmm1, 0x10	; Generating round key 11
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*11], xmm4

        aeskeygenassist xmm2, xmm4, 0x20	; Generating round key 12
        key_expansion_256_sse
	MOVDQ_KEYS	[EXP_KEYS + 16*12], xmm1
		
        aeskeygenassist xmm2, xmm1, 0x20	; Generating round key 13
        key_expansion_256_sse_2
	MOVDQ_KEYS	[EXP_KEYS + 16*13], xmm4

        aeskeygenassist xmm2, xmm4, 0x40	; Generating round key 14 
        key_expansion_256_sse        
	MOVDQ_KEYS	[EXP_KEYS + 16*14], xmm1

	ret


; void aes_keyexp_256_dec(UINT128 *key,
;                         UINT128 *dec_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for decrypt
;
global aes_keyexp_256_dec :function
aes_keyexp_256_dec:
        movdqu	xmm1, [KEY]			; loading the AES key
        MOVDQ_KEYS	[EXP_KEYS + 16*0], xmm1	; Storing key in memory
        
        movdqu	xmm4, [KEY+16]			; loading the AES key
        aesimc	xmm0, xmm4
        MOVDQ_KEYS	[EXP_KEYS + 16*1], xmm0	; Storing key in memory
                        
        pxor xmm3, xmm3				; Required for the key_expansion.

        aeskeygenassist xmm2, xmm4, 0x1		; Generating round key 2 
        key_expansion_256_sse
	aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*2], xmm5			     
        
        aeskeygenassist xmm2, xmm1, 0x1		; Generating round key 3
        key_expansion_256_sse_2
        aesimc	xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*3], xmm0

        aeskeygenassist xmm2, xmm4, 0x2		; Generating round key 4 
        key_expansion_256_sse
        aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*4], xmm5
        
        aeskeygenassist xmm2, xmm1, 0x2		; Generating round key 5
        key_expansion_256_sse_2
        aesimc	xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*5], xmm0

        aeskeygenassist xmm2, xmm4, 0x4		; Generating round key 6 
        key_expansion_256_sse
        aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*6], xmm5
		
        aeskeygenassist xmm2, xmm1, 0x4		; Generating round key 7
        key_expansion_256_sse_2
        aesimc xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*7], xmm0

        aeskeygenassist xmm2, xmm4, 0x8		; Generating round key 8 
        key_expansion_256_sse
        aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*8], xmm5
		
        aeskeygenassist xmm2, xmm1, 0x8		; Generating round key 9
        key_expansion_256_sse_2
        aesimc	xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*9], xmm0

        aeskeygenassist xmm2, xmm4, 0x10	; Generating round key 10
        key_expansion_256_sse
        aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*10], xmm5
		
        aeskeygenassist xmm2, xmm1, 0x10	; Generating round key 11
        key_expansion_256_sse_2
        aesimc	xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*11], xmm0

        aeskeygenassist xmm2, xmm4, 0x20	; Generating round key 12
        key_expansion_256_sse
        aesimc	xmm5, xmm1
	MOVDQ_KEYS	[EXP_KEYS + 16*12], xmm5
		
        aeskeygenassist xmm2, xmm1, 0x20	; Generating round key 13
        key_expansion_256_sse_2
        aesimc	xmm0, xmm4				
	MOVDQ_KEYS	[EXP_KEYS + 16*13], xmm0

        aeskeygenassist xmm2, xmm4, 0x40	; Generating round key 14 
        key_expansion_256_sse        
	MOVDQ_KEYS	[EXP_KEYS + 16*14], xmm1

	ret

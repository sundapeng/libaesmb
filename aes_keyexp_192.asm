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

;; assume keys are not aligned
%define MOVDQ_KEYS movdqu


%macro key_expansion_1_192_enc 1
	;; Assumes the xmm3 includes all zeros at this point. 
        pshufd xmm2, xmm2, 11111111b        
        shufps xmm3, xmm1, 00010000b        
        pxor xmm1, xmm3        
        shufps xmm3, xmm1, 10001100b
        pxor xmm1, xmm3        
	pxor xmm1, xmm2		
	movdqu [EXP_KEYS+%1], xmm1			
%endmacro

; Calculate w10 and w11 using calculated w9 and known w4-w5
%macro key_expansion_2_192_enc 1				
		movdqa xmm5, xmm4
		pslldq xmm5, 4
		shufps xmm6, xmm1, 11110000b
		pxor xmm6, xmm5
		pxor xmm4, xmm6
		pshufd xmm7, xmm4, 00001110b 
		movdqu [EXP_KEYS+%1], xmm7
%endmacro

%macro key_dec_192 1
  	MOVDQ_KEYS  xmm0, [EXP_KEYS + 16 * %1]
	aesimc	xmm1, xmm0
	MOVDQ_KEYS [EXP_KEYS + 16 * %1], xmm1
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

; void aes_keyexp_192_enc(UINT128 *key,
;                         UINT128 *enc_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for encrypt
;
global aes_keyexp_192_enc :function
aes_keyexp_192_enc:

%ifdef WINABI
	sub	rsp, 16*2 + 8
	movdqa	[rsp + 0*16], xmm6
	movdqa	[rsp + 1*16], xmm7
%endif

	movq xmm7, [KEY + 16]	; loading the AES key, 64 bits
        movq [EXP_KEYS + 16], xmm7  ; Storing key in memory where all key expansion 
        pshufd xmm4, xmm7, 01001111b
        movdqu xmm1, [KEY]	; loading the AES key, 128 bits
        movdqu [EXP_KEYS], xmm1  ; Storing key in memory where all key expansion 
	
        pxor xmm3, xmm3		; Set xmm3 to be all zeros. Required for the key_expansion. 
        pxor xmm6, xmm6		; Set xmm3 to be all zeros. Required for the key_expansion. 

        aeskeygenassist xmm2, xmm4, 0x1     ; Complete round key 1 and generate round key 2 
        key_expansion_1_192_enc 24
		key_expansion_2_192_enc 40				

        aeskeygenassist xmm2, xmm4, 0x2     ; Generate round key 3 and part of round key 4
        key_expansion_1_192_enc 48
		key_expansion_2_192_enc 64				

        aeskeygenassist xmm2, xmm4, 0x4     ; Complete round key 4 and generate round key 5
        key_expansion_1_192_enc 72
		key_expansion_2_192_enc 88
		
        aeskeygenassist xmm2, xmm4, 0x8     ; Generate round key 6 and part of round key 7
        key_expansion_1_192_enc 96
		key_expansion_2_192_enc 112
		
        aeskeygenassist xmm2, xmm4, 0x10     ; Complete round key 7 and generate round key 8 
        key_expansion_1_192_enc 120
		key_expansion_2_192_enc 136				

        aeskeygenassist xmm2, xmm4, 0x20     ; Generate round key 9 and part of round key 10
        key_expansion_1_192_enc 144
		key_expansion_2_192_enc 160				

        aeskeygenassist xmm2, xmm4, 0x40     ; Complete round key 10 and generate round key 11
        key_expansion_1_192_enc 168
		key_expansion_2_192_enc 184				

        aeskeygenassist xmm2, xmm4, 0x80     ; Generate round key 12
        key_expansion_1_192_enc 192

%ifdef WINABI
	movdqa	xmm6, [rsp + 0*16]
	movdqa	xmm7, [rsp + 1*16]
	add	rsp, 16*2 + 8
%endif

     ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; void aes_keyexp_192_dec(UINT128 *key,
;                         UINT128 *dec_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for decrypt
;
global aes_keyexp_192_dec :function
aes_keyexp_192_dec:

%ifdef WINABI
	sub	rsp, 16*2 + 8
	movdqa	[rsp + 0*16], xmm6
	movdqa	[rsp + 1*16], xmm7
%endif

	movq xmm7, [KEY + 16]	; loading the AES key, 64 bits
        movq [EXP_KEYS + 16], xmm7  ; Storing key in memory where all key expansion 
        pshufd xmm4, xmm7, 01001111b
        movdqu xmm1, [KEY]	; loading the AES key, 128 bits
        MOVDQ_KEYS [EXP_KEYS], xmm1  ; Storing key in memory where all key expansion 
        pxor xmm3, xmm3		; Set xmm3 to be all zeros. Required for the key_expansion. 
        pxor xmm6, xmm6		; Set xmm3 to be all zeros. Required for the key_expansion. 

        aeskeygenassist xmm2, xmm4, 0x1     ; Complete round key 1 and generate round key 2 
        key_expansion_1_192_enc 24
		key_expansion_2_192_enc 40				

        aeskeygenassist xmm2, xmm4, 0x2     ; Generate round key 3 and part of round key 4
        key_expansion_1_192_enc 48
		key_expansion_2_192_enc 64				

        aeskeygenassist xmm2, xmm4, 0x4     ; Complete round key 4 and generate round key 5
        key_expansion_1_192_enc 72
		key_expansion_2_192_enc 88
		
        aeskeygenassist xmm2, xmm4, 0x8     ; Generate round key 6 and part of round key 7
        key_expansion_1_192_enc 96
		key_expansion_2_192_enc 112
		
        aeskeygenassist xmm2, xmm4, 0x10     ; Complete round key 7 and generate round key 8 
        key_expansion_1_192_enc 120
		key_expansion_2_192_enc 136				

        aeskeygenassist xmm2, xmm4, 0x20     ; Generate round key 9 and part of round key 10
        key_expansion_1_192_enc 144
		key_expansion_2_192_enc 160				

        aeskeygenassist xmm2, xmm4, 0x40     ; Complete round key 10 and generate round key 11
        key_expansion_1_192_enc 168
		key_expansion_2_192_enc 184				

        aeskeygenassist xmm2, xmm4, 0x80     ; Generate round key 12
        key_expansion_1_192_enc 192

;;;  generate remaining decrypt keys	
     key_dec_192 1
     key_dec_192 2	
     key_dec_192 3
     key_dec_192 4
     key_dec_192 5
     key_dec_192 6	
     key_dec_192 7
     key_dec_192 8
     key_dec_192 9	
     key_dec_192 10
     key_dec_192 11

%ifdef WINABI
	movdqa	xmm6, [rsp + 0*16]
	movdqa	xmm7, [rsp + 1*16]
	add	rsp, 16*2 + 8
%endif

     ret

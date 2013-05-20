/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdint.h>

typedef struct _sAesData {
    uint8_t *inbuf;
    uint8_t *outbuf;
    uint8_t *keysched;
    uint8_t *iv;
    uint64_t numblocks;
} sAesData;

typedef struct _sAesData_x8 {
    uint8_t *inbuf[8];
    uint8_t *outbuf[8];
    uint8_t *keysched;
    uint8_t *iv[8];
    uint64_t numblocks;
} sAesData_x8;

// Multi-buffer: The same key is applied to all streams
void aes_cbc_enc_128_x8(sAesData_x8 *args);
void aes_cbc_enc_192_x8(sAesData_x8 *args);
void aes_cbc_enc_256_x8(sAesData_x8 *args);

// Single Buffer:
void iDec128_CBC_by8(sAesData *data);
void iDec192_CBC_by8(sAesData *data);
void iDec256_CBC_by8(sAesData *data);

// Key Expansion:
void aes_keyexp_128_enc(uint8_t *key, uint8_t *enc_exp_keys);
void aes_keyexp_192_enc(uint8_t *key, uint8_t *enc_exp_keys);
void aes_keyexp_256_enc(uint8_t *key, uint8_t *enc_exp_keys);
void aes_keyexp_128_dec(uint8_t *key, uint8_t *dec_exp_keys);
void aes_keyexp_192_dec(uint8_t *key, uint8_t *dec_exp_keys);
void aes_keyexp_256_dec(uint8_t *key, uint8_t *dec_exp_keys);

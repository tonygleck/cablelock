// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"

#include "cablelock/crypto_ciphers.h"
#include "cablelock/crypto_macro.h"

#define AES_BLOCK_SIZE      16
#define AES_128_KEY_SIZE    16
#define AES_256_KEY_SIZE    32

static const int sbox[16][16] = {
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};

static unsigned char inv_sbox[16][16] = {
    { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
    { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
    { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
    { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
    { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xb4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
    { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
    { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
    { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
    { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
    { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
    { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
    { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
    { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f }
};

static void rotate_word(unsigned char* value)
{
    unsigned char tmp = value[0];
    value[0] = value[1];
    value[1] = value[2];
    value[2] = value[3];
    value[3] = tmp;
}

static void inv_substitute_byte(unsigned char state[][4])
{
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            state[index][inner] = inv_sbox[(state[index][inner] & 0xF0) >> 4][state[index][inner] & 0x0F];
        }
    }
}

static void substitute_byte(unsigned char state[][4])
{
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            state[index][inner] = sbox[(state[index][inner] & 0xF0) >> 4][state[index][inner] & 0x0F];
        }
    }
}

static void substitute_word(unsigned char* value)
{
    for (size_t index = 0; index < 4; index++)
    {
        value[index] = sbox[(value[index]&0xF0) >> 4][value[index] & 0x0f];
    }
}

static void add_round_key(unsigned char state[][4], unsigned char key_sched[][4])
{
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            state[inner][index] = state[inner][index] ^ key_sched[index][inner];
        }
    }
}

static void compute_key_schedule(const unsigned char* key, size_t key_len, unsigned char key_sched[][4])
{
    size_t key_word = key_len >> 2;
    unsigned char rcon = 0x01;

    memcpy(key_sched, key, key_len);
    for (size_t index = 0; index < 4*(key_word+7); index++)
    {
        memcpy(key_sched[index], key_sched[index - 1], 4);
        if (!(index % key_word))
        {
            rotate_word(key_sched[index]);
            substitute_word(key_sched[index]);
            if (!(index % 36))
            {
                rcon = 0x1b;
            }
            key_sched[index][0] = rcon;
            rcon <<= 1;
        }
        else if ((key_word > 6) && ((index % key_word) == 4))
        {
            substitute_word(key_sched[index]);
        }
        key_sched[index][0] ^= key_sched[index - key_word][0];
        key_sched[index][1] ^= key_sched[index - key_word][1];
        key_sched[index][2] ^= key_sched[index - key_word][2];
        key_sched[index][3] ^= key_sched[index - key_word][3];
    }
}

static void inv_shift_rows(unsigned char state[][4])
{
    unsigned char tmp = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

static void shift_rows(unsigned char state[][4])
{
    unsigned char tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

// xtime is a math term
static unsigned char xtime(unsigned char value)
{
    return (value << 1) ^ ((value & 0x80) ? 0x1b : 0x00);
}

// This function implements multipliccation
unsigned char dot_product(unsigned char value, unsigned char y)
{
    unsigned char product = 0;
    for (unsigned char mask = 0x01; mask; mask <<= 1)
    {
        if (y & mask)
        {
            product ^= value;
        }
        value = xtime(value);
    }
    return product;
}

// Doing a matrix multiplication
static void mix_column(unsigned char value[][4])
{
    unsigned char tmp[4];
    for (size_t index = 0; index < 4; index++)
    {
        tmp[0] = dot_product(2, value[0][index]) ^ dot_product(3, value[1][index]) ^ value[2][index] ^ value[3][index];
        tmp[1] = value[0][index] ^ dot_product(2, value[1][index]) ^ dot_product(3, value[2][index]) ^ value[3][index];
        tmp[2] = value[0][index] ^ value[1][index] ^ dot_product(2, value[2][index]) ^ dot_product(3, value[3][index]);
        tmp[3] = dot_product(3, value[0][index]) ^ value[1][index] ^ value[2][index] ^ dot_product(2, value[3][index]);
        value[0][index] = tmp[0];
        value[1][index] = tmp[1];
        value[2][index] = tmp[2];
        value[3][index] = tmp[3];
    }
}

static void inv_mix_column(unsigned char value[][4])
{
    unsigned char tmp[4];
    for (size_t index = 0; index < 4; index++)
    {
        tmp[0] = dot_product(0x0e, value[0][index]) ^ dot_product(0x0b, value[1][index]) ^ dot_product(0x0d, value[2][index]) ^ dot_product(0x09, value[3][0]);
        tmp[1] = dot_product(0x09, value[0][index]) ^ dot_product(0x0e, value[1][index]) ^ dot_product(0x0b, value[2][index]) ^ dot_product(0x0d, value[3][0]);
        tmp[2] = dot_product(0x0d, value[0][index]) ^ dot_product(0x09, value[1][index]) ^ dot_product(0x0e, value[2][index]) ^ dot_product(0x0b, value[3][0]);
        tmp[3] = dot_product(0x0b, value[0][index]) ^ dot_product(0x0d, value[1][index]) ^ dot_product(0x09, value[2][index]) ^ dot_product(0x0e, value[3][0]);

        value[0][index] = tmp[0];
        value[1][index] = tmp[1];
        value[2][index] = tmp[2];
        value[3][index] = tmp[3];
    }
}

static void matrix_multiply(unsigned char m1[4][4], unsigned char m2[4][4], unsigned char target[4][4])
{
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            target[index][inner] =
            m1[index][0] * m2[0][inner] +
            m1[index][1] * m2[1][inner] +
            m1[index][2] * m2[2][inner] +
            m1[index][3] * m2[3][inner];
        }
    }
}

static void block_encrypt(const unsigned char* input_block, unsigned char* output_block, const unsigned char* key, size_t key_len)
{
    unsigned char state[4][4];
    // Allocate enough for 256-bit key
    unsigned char w[60][4];
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            state[index][inner] = input_block[index+(4*inner)];
        }
    }
    // Rounds equals key size in 4 byte words + 6
    size_t num_rounds = (key_len >> 2) + 6;

    compute_key_schedule(key, key_len, w);
    add_round_key(state, &w[0]);

    for (size_t index = 0; index < num_rounds; index++)
    {
        substitute_byte(state);
        shift_rows(state);
        if (index < (num_rounds - 1))
        {
            mix_column(state);
        }
        add_round_key(state, &w[(index+1)*4]);
    }

    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            output_block[index+(4*inner)] = state[index][inner];
        }
    }
}

static void block_decrypt(const unsigned char* input_block, unsigned char* output_block, const unsigned char* key, size_t key_len)
{
    unsigned char state[4][4];
    // Allocate enough for 256-bit key
    unsigned char w[60][4];

    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            state[index][inner] = input_block[index+(4*inner)];
        }
    }
    // Rounds equals key size in 4 byte words + 6
    size_t num_rounds = (key_len >> 2) + 6;

    compute_key_schedule(key, key_len, w);
    add_round_key(state, &w[num_rounds*4]);

    for (size_t index = 0; index < num_rounds; index++)
    {
        inv_shift_rows(state);
        inv_substitute_byte(state);
        add_round_key(state, &w[(index-1)*4]);
        if (index > 1)
        {
            inv_mix_column(state);
        }
    }
    for (size_t index = 0; index < 4; index++)
    {
        for (size_t inner = 0; inner < 4; inner++)
        {
            output_block[index+(4*inner)] = state[index][inner];
        }
    }
}

static void aes_encrypt_value(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output,
    const unsigned char* key, size_t key_len, unsigned char* init_vector)
{
    unsigned char input_block[AES_BLOCK_SIZE];

    while (cipher_len >= AES_BLOCK_SIZE)
    {
        memcpy(input_block, cipher_text, AES_BLOCK_SIZE);
        // implement CBC
        xor_value(input_block, init_vector, AES_BLOCK_SIZE);
        block_encrypt(input_block, output, key, key_len);
        memcpy(init_vector, output, AES_BLOCK_SIZE);
        cipher_text += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
        cipher_len -= AES_BLOCK_SIZE;
    }
}

static void aes_decrypt_value(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output,
    const unsigned char* key, size_t key_len, unsigned char* init_vector)
{
    while (cipher_len >= AES_BLOCK_SIZE)
    {
        block_decrypt(cipher_text, output, key, key_len);
        xor_value(output, init_vector, AES_BLOCK_SIZE);
        memcpy(init_vector, cipher_text, AES_BLOCK_SIZE);
        cipher_text += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
        cipher_len -= AES_BLOCK_SIZE;
    }
}

int crypto_aes_encrypt_128(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output, size_t result_len,
    const unsigned char* key, const unsigned char* init_vector, bool add_padding)
{
    int result;
    (void)add_padding;
    (void)result_len;
    if (cipher_text == NULL || cipher_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified cipher_text: %p, cipher_len: %d, output: %p, key: %p", cipher_text, (int)cipher_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* iv_value = NULL;
        unsigned char iv_item[AES_BLOCK_SIZE];
        if (init_vector != NULL)
        {
            memcpy(iv_item, init_vector, AES_BLOCK_SIZE);
            iv_value = iv_item;
        }
        aes_encrypt_value(cipher_text, cipher_len, output, key, AES_128_KEY_SIZE, iv_value);
        result = __LINE__;
    }
    return result;
}

int crypto_aes_decrypt_128(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output, size_t result_len,
    const unsigned char* key, const unsigned char* init_vector, bool is_padded)
{
    int result;
    (void)is_padded;
    (void)result_len;
    if (cipher_text == NULL || cipher_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified cipher_text: %p, cipher_len: %d, output: %p, key: %p", cipher_text, (int)cipher_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* iv_value = NULL;
        unsigned char iv_item[AES_BLOCK_SIZE];
        if (init_vector != NULL)
        {
            memcpy(iv_item, init_vector, AES_BLOCK_SIZE);
            iv_value = iv_item;
        }
        aes_decrypt_value(cipher_text, cipher_len, output, key, AES_128_KEY_SIZE, iv_value);
        result = __LINE__;
    }
    return result;
}

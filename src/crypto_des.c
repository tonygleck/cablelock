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

#define DES_KEY_SIZE            8
#define DES_BLOCK_SIZE          8   // 64 bits
#define EXPANSION_BLOCK_SIZE    6
#define PC1_KEY_SIZE            7
#define SUBKEY_SIZE             6
#define ROUND_KEY_SCHEDULE_NUM  16

typedef enum CRYPTO_OPERATION_TAG
{
    CRYPTO_ENCRYPT = 0x01,
    CRYPTO_TRIPLE_DES = 0x02
} CRYPTO_OPERATION;

static const int initial_perm_table[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int final_perm_table[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

static const int pc1_table[] = {
    57, 49, 41, 33, 25, 17,  9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5,
    28, 20, 12,  4
};

static const int pc2_table[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int expansion_table[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// simple lookup table for the s-box
static const int sbox[8][64] = {
    {
        14,  0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
        3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
        4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
        15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13
    },
    {
        15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
        9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
        0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
        5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
    },
    {
        10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
        1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
        13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
        11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12
    },
    {
        7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
        1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
        10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
        15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14
    },
    {
        2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
        8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
        4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
        15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3
    },
    {
        12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
        0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
        9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
        7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13
    },
    {
        4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
        3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
        1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
        10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12
    },
    {
        13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
        10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
        7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
        0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
    }
};

static const int p_table[] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

// Overwrite target array with the XOR of the src array
// static void xor_value(unsigned char* target, const unsigned char* src, size_t length)
// {
//     while (length--)
//     {
//         *target++ ^= *src++;
//     }
// }

// Implement the initial and final permutation functions. permute_table
// and target must have exactly len and len * 8 number of entries,
// respectively, but src can be shorter (expansion function depends on this).
// NOTE: this assumes that the permutation tables are defined as one-based
// rather than 0-based arrays, since they're given that way in the
// specification.
static void permute_routine(unsigned char target[], const unsigned char src[], const int permute_table[], size_t length)
{
    for (size_t index = 0; index < length * 8; index++)
    {
        if (GET_BIT(src, (permute_table[index] - 1)))
        {
            SET_BIT(target, index);
        }
        else
        {
            CLEAR_BIT(target, index);
        }
    }
}

static void rotate_left(unsigned char* target)
{
    unsigned char carry_left;
    unsigned char carry_right;

    carry_left = (target[0] & 0x80) >> 3;

    target[0] = (target[0] << 1) | ((target[1] & 0x80) >> 7);
    target[1] = (target[1] << 1) | ((target[2] & 0x80) >> 7);
    target[2] = (target[2] << 1) | ((target[3] & 0x80) >> 7);

    // Special handling for byte 3
    carry_right = (target[3] & 0x08) >> 3;
    target[3] = (((target[3] << 1) | ((target[4] & 0x80) >> 7)) & ~0x10) | carry_left;

    target[4] = (target[4] << 1) | ((target[5] & 0x80) >> 7);
    target[5] = (target[5] << 1) | ((target[6] & 0x80) >> 7);
    target[6] = (target[6] << 1) | carry_right;
}

static void rotate_right(unsigned char* target)
{
    unsigned char carry_left;
    unsigned char carry_right;

    carry_right = (target[6] & 0x01) << 3;

    target[6] = (target[6] >> 1) | ((target[5] & 0x01) << 7);
    target[5] = (target[5] >> 1) | ((target[4] & 0x01) << 7);
    target[4] = (target[4] >> 1) | ((target[3] & 0x01) << 7);

    // Special handling for byte 3
    carry_left = (target[3] & 0x10) << 3;
    target[3] = (((target[3] >> 1) | ((target[2] & 0x01) << 7)) & ~0x08) | carry_right;

    target[2] = (target[2] >> 1) | ((target[1] & 0x01) << 7);
    target[1] = (target[1] >> 1) | ((target[0] & 0x01) << 7);
    target[0] = (target[0] >> 1) | carry_left;
}

static void des_block_operate(uint32_t operation, const unsigned char plain_text[DES_BLOCK_SIZE], unsigned char cipher_text[DES_BLOCK_SIZE], const unsigned char key[DES_KEY_SIZE])
{
    unsigned char ip_block[DES_BLOCK_SIZE];
    unsigned char sub_block[DES_BLOCK_SIZE/2];
    unsigned char pbox_target[DES_BLOCK_SIZE/2];
    unsigned char recomb_box[DES_BLOCK_SIZE/2];

    unsigned char pc1_key[PC1_KEY_SIZE];
    unsigned char expansion_block[EXPANSION_BLOCK_SIZE];
    unsigned char sub_key[SUBKEY_SIZE];

    // Initial Permutation
    permute_routine(ip_block, plain_text, initial_perm_table, DES_BLOCK_SIZE);

    // Key Schedule computation
    permute_routine(pc1_key, key, pc1_table, PC1_KEY_SIZE);

    for (size_t index = 0; index < 16; index++)
    {
        // "Feistel function" on the first half of the block in 'ip_block'
        // "Expansion": This permutation only looks at the first 4 bytes (32 bits)
        // 16 of these are repeated in "expansion_table"
        permute_routine(expansion_block, ip_block+4, expansion_table, 6);

        // Key mixing
        // Rotate both halves of the initial key
        if (operation & CRYPTO_ENCRYPT)
        {
            rotate_left(pc1_key);
            if (!(index <= 1 || index == 8 || index == 15))
            {
                // Rotate twice except in the 1st, 2nd, 9th & 16th round
                rotate_left(pc1_key);
            }
        }

        permute_routine(sub_key, pc1_key, pc2_table, SUBKEY_SIZE);

        if (!(operation & CRYPTO_ENCRYPT))
        {
            rotate_right(pc1_key);
            if (!(index >= 14 || index == 7 || index == 0))
            {
                // Rotate twice except in the 1st, 2nd, 9th & 16th rounds
                rotate_right(pc1_key);
            }
        }

        xor_value(expansion_block, sub_key, 6);

        // Update from updated expansion block to cipher block
        memset(sub_block, 0, DES_BLOCK_SIZE/2);
        sub_block[0] = sbox[0][(expansion_block[0] & 0xFC) >> 2] << 4;
        sub_block[0] |= sbox[1][(expansion_block[0] & 0x03) << 4 | (expansion_block[1] & 0x0F) >> 4];
        sub_block[1] = sbox[2][(expansion_block[1] & 0x0F) << 2 | (expansion_block[2] & 0xC0) >> 6] << 4;
        sub_block[1] |= sbox[3][(expansion_block[2] & 0x3F)];
        sub_block[2] = sbox[4][(expansion_block[3] & 0xFC) >> 2] << 4;
        sub_block[2] |= sbox[5][(expansion_block[3] & 0x03) << 4 | (expansion_block[4] & 0x0F >> 4)];
        sub_block[3] = sbox[6][(expansion_block[4] & 0x0F) << 2 | (expansion_block[5] & 0xC0) >> 6] << 4;
        sub_block[3] |= sbox[7][(expansion_block[5] & 0x3F)];

        permute_routine(pbox_target, sub_block, p_table, DES_BLOCK_SIZE / 2);

        // Recombination: XOR the pbox with left half and then switch sides
        memcpy(recomb_box, ip_block, DES_BLOCK_SIZE/2);
        memcpy(ip_block, (ip_block+4), DES_BLOCK_SIZE/2);
        xor_value(recomb_box, pbox_target, DES_BLOCK_SIZE/2);
        memcpy(ip_block+4, recomb_box, DES_BLOCK_SIZE/2);
    }

    // One last swap
    memcpy(recomb_box, ip_block, DES_BLOCK_SIZE/2);
    memcpy(ip_block, (ip_block+4), DES_BLOCK_SIZE/2);
    memcpy(ip_block+4, recomb_box, DES_BLOCK_SIZE/2);

    // Final Permutation (undoing the initial)
    permute_routine(cipher_text, ip_block, final_perm_table, DES_BLOCK_SIZE);
}

static int des_operation(uint32_t operation, const unsigned char* input, size_t input_len,
    unsigned char* output, size_t output_len, const unsigned char* key, unsigned char* init_vector)
{
    int result;
    unsigned char input_block[DES_BLOCK_SIZE];
    if (input_len % DES_BLOCK_SIZE || output_len < input_len)
    {
        log_error("The input len must be divisible by 8 and the result len must be > or = input len");
        result = __LINE__;
    }
    else
    {
        while (input_len)
        {
            memcpy(input_block, input, DES_BLOCK_SIZE);
            if (operation & CRYPTO_ENCRYPT)
            {
                if (init_vector != NULL)
                {
                    // Implement Cipher Block Chaining (CBC)
                    xor_value(input_block, init_vector, DES_BLOCK_SIZE);
                }
                des_block_operate(operation, input_block, output, key);
                if (operation & CRYPTO_TRIPLE_DES)
                {
                    memcpy(input_block, output, DES_BLOCK_SIZE);
                    des_block_operate(operation, input_block, output, key+DES_KEY_SIZE);

                    memcpy(input_block, output, DES_BLOCK_SIZE);
                    des_block_operate(operation, input_block, output, key+(DES_KEY_SIZE*2));
                }
                if (init_vector != NULL)
                {
                    // For CBC
                    memcpy(init_vector, output, DES_BLOCK_SIZE);
                }
            }
            else
            {
                if (operation & CRYPTO_TRIPLE_DES)
                {
                    des_block_operate(operation, input_block, output, key+(DES_KEY_SIZE*2));
                    memcpy(input_block, output, DES_BLOCK_SIZE);
                    des_block_operate(operation, input_block, output, key+DES_KEY_SIZE);
                    memcpy(input_block, output, DES_BLOCK_SIZE);
                }
                des_block_operate(operation, input_block, output, key);
                if (init_vector != NULL)
                {
                    // Implement Cipher Block Chaining
                    xor_value(output, init_vector, DES_BLOCK_SIZE);
                    memcpy(init_vector, input, DES_BLOCK_SIZE);
                }
            }
            input += DES_BLOCK_SIZE;
            input_len -= DES_BLOCK_SIZE;
            output += DES_BLOCK_SIZE;
        }
        result = 0;
    }
    return result;
}

int crypto_des_encrypt(const unsigned char* input, size_t input_len, unsigned char* output, size_t result_len,
    const unsigned char* key, const unsigned char* init_vector, bool add_padding)
{
    int result;
    (void)result_len;

    int j = input_len % DES_BLOCK_SIZE;
    if (input == NULL || input_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified input: %p, cipher_len: %d, output: %p, key: %p", input, (int)input_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* padded_input = (unsigned char*)input;
        size_t padded_len = 0;
        if (add_padding)
        {
            // Adding PKCS #5 padding to the input
            padded_len = DES_BLOCK_SIZE - (input_len % DES_BLOCK_SIZE);
            if ((padded_input = (unsigned char*)malloc(padded_len + input_len)) == NULL)
            {
                log_error("Failure allocating padded text length");
                result = __LINE__;
            }
            else
            {
                memset(padded_input, padded_len, padded_len + input_len);
                memcpy(padded_input, input, input_len);
                result = 0;
            }
        }
        else
        {
            result = 0;
        }

        if (result == 0)
        {
            unsigned char* iv_value = NULL;
            unsigned char iv_item[DES_BLOCK_SIZE];
            if (init_vector != NULL)
            {
                memcpy(iv_item, init_vector, DES_BLOCK_SIZE);
                iv_value = iv_item;
            }

            result = des_operation(CRYPTO_ENCRYPT, padded_input, padded_len + input_len, output, result_len, key, iv_value);
            if (add_padding)
            {
                free(padded_input);
            }
        }
    }
    return result;
}

int crypto_des_decrypt(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output,
    size_t result_len, const unsigned char* key, const unsigned char* init_vector, bool is_padded)
{
    int result;
    (void)result_len;
    if (cipher_text == NULL || cipher_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified cipher_text: %p, cipher_len: %d, output: %p, key: %p", cipher_text, (int)cipher_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* iv_value = NULL;
        unsigned char iv_item[DES_BLOCK_SIZE];
        if (init_vector != NULL)
        {
            memcpy(iv_item, init_vector, DES_BLOCK_SIZE);
            iv_value = iv_item;
        }

        result = des_operation(0, cipher_text, cipher_len, output, result_len, key, iv_value);
        if (is_padded)
        {
            // Remove PKCS #5 padding
            output[cipher_len-output[cipher_len-1]] = 0x0;
        }
    }
    return result;
}

int crypto_3des_encrypt(const unsigned char* input, size_t input_len, unsigned char* output, size_t result_len,
    const unsigned char* key, const unsigned char* init_vector, bool add_padding)
{
    int result;
    (void)result_len;

    int j = input_len % DES_BLOCK_SIZE;
    if (input == NULL || input_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified input: %p, cipher_len: %d, output: %p, key: %p", input, (int)input_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* padded_input = (unsigned char*)input;
        size_t padded_len = 0;
        if (add_padding)
        {
            // Adding PKCS #5 padding to the input
            padded_len = DES_BLOCK_SIZE - (input_len % DES_BLOCK_SIZE);
            if ((padded_input = (unsigned char*)malloc(padded_len + input_len)) == NULL)
            {
                log_error("Failure allocating padded text length");
                result = __LINE__;
            }
            else
            {
                memset(padded_input, padded_len, padded_len + input_len);
                memcpy(padded_input, input, input_len);
                result = 0;
            }
        }
        else
        {
            result = 0;
        }

        if (result == 0)
        {
            unsigned char* iv_value = NULL;
            unsigned char iv_item[DES_BLOCK_SIZE];
            if (init_vector != NULL)
            {
                memcpy(iv_item, init_vector, DES_BLOCK_SIZE);
                iv_value = iv_item;
            }

            des_operation(CRYPTO_ENCRYPT|CRYPTO_TRIPLE_DES, padded_input, padded_len + input_len, output, result_len, key, iv_value);
            if (add_padding)
            {
                free(padded_input);
            }
        }
    }
    return result;
}

int crypto_3des_decrypt(const unsigned char* cipher_text, size_t cipher_len, unsigned char* output,
    size_t result_len, const unsigned char* key, const unsigned char* init_vector, bool is_padded)
{
    int result;
    if (cipher_text == NULL || cipher_len == 0 || output == NULL || key == NULL)
    {
        log_error("Failure invalid parameter specified cipher_text: %p, cipher_len: %d, output: %p, key: %p", cipher_text, (int)cipher_len, output, key);
        result = __LINE__;
    }
    else
    {
        unsigned char* iv_value = NULL;
        unsigned char iv_item[DES_BLOCK_SIZE];
        if (init_vector != NULL)
        {
            memcpy(iv_item, init_vector, DES_BLOCK_SIZE);
            iv_value = iv_item;
        }

        result = des_operation(CRYPTO_TRIPLE_DES, cipher_text, cipher_len, output, result_len, key, iv_value);
        if (is_padded)
        {
            // Remove PKCS #5 padding
            output[cipher_len-output[cipher_len-1]] = 0x0;
        }
    }
    return result;
}

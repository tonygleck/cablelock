#pragma once

#ifdef __cplusplus
extern "C" {
    #include <cstdlib>
#else
    #include <stdlib.h>
    #include <stdbool.h>
#endif

#include "umock_c/umock_c_prod.h"

MOCKABLE_FUNCTION(, int, crypto_des_encrypt, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, add_padding);
MOCKABLE_FUNCTION(, int, crypto_des_decrypt, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, is_padded);

MOCKABLE_FUNCTION(, int, crypto_3des_encrypt, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, add_padding);
MOCKABLE_FUNCTION(, int, crypto_3des_decrypt, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, is_padded);

MOCKABLE_FUNCTION(, int, crypto_aes_encrypt_128, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, add_padding);
MOCKABLE_FUNCTION(, int, crypto_aes_decrypt_128, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, is_padded);
MOCKABLE_FUNCTION(, int, crypto_aes_encrypt_256, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, add_padding);
MOCKABLE_FUNCTION(, int, crypto_aes_decrypt_256, const unsigned char*, cipher_text, size_t, cipher_len, unsigned char*, output, size_t, result_len,
    const unsigned char*, key, const unsigned char*, init_vector, bool, is_padded);

#ifdef __cplusplus
}
#endif

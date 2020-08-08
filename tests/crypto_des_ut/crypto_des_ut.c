// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#include <cstdio>
#else
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#endif

static void* my_mem_shim_malloc(size_t size)
{
    return malloc(size);
}

static void my_mem_shim_free(void* ptr)
{
    free(ptr);
}

#include "ctest.h"
#include "umock_c/umock_c_prod.h"
#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umock_c_negative_tests.h"
#include "azure_macro_utils/macro_utils.h"

#define ENABLE_MOCKS
#include "lib-util-c/sys_debug_shim.h"
#undef ENABLE_MOCKS

#include "cablelock/crypto_ciphers.h"

static const char* TEST_ENCRYPT_DATA = "abcdefghijklmnop";
static const char* TEST_KEY_DATA = "password";
static const char* TEST_3DES_KEY_DATA = "twentyfourcharacterinput";
static const char* TEST_INITIAL_VECTOR = "initialz";
static const size_t TEST_ENCRYPT_DATA_LEN = 16;
static const unsigned char TEST_CIPHER_DATA[] = { 0xf1, 0xf2, 0xe9, 0x72, 0x56, 0xb5, 0xb2, 0xd0, 0xff, 0x69, 0xd4, 0x99, 0x69, 0xd1, 0x73, 0x09 };
static const unsigned char TEST_3DES_CIPHER_DATA[] = { 0xa4, 0x75, 0xa0, 0xc2, 0x2a, 0x11, 0xca, 0xa4, 0xe9, 0x29, 0x47, 0x6b, 0xc7, 0xb3, 0x98, 0x9e };

static const unsigned char TEST_NO_INIT_CIPHER_DATA[] = { 0x16, 0x0b, 0x3b, 0x0e, 0xea, 0x65, 0x62, 0x49, 0x75, 0xc9, 0xf6, 0x67, 0x13, 0x9a, 0x0d, 0x2e };
static const unsigned char TEST_3DES_NO_INIT_CIPHER_DATA[] = { 0xc8, 0x7c, 0xe0, 0x7c, 0x0b, 0xf0, 0xd3, 0x6b, 0xc6, 0x1c, 0x15, 0xdb, 0xdc, 0x25, 0x1c, 0x3f };

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(crypto_des_ut)

    CTEST_SUITE_INITIALIZE()
    {
        int result;

        (void)umock_c_init(on_umock_c_error);

        //REGISTER_TYPE(const cord_socket_CONFIG*, const_cord_socket_CONFIG_ptr);
        //REGISTER_UMOCK_ALIAS_TYPE(cord_socket_CONFIG*, const cord_socket_CONFIG*);

        REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);
    }

    CTEST_SUITE_CLEANUP()
    {
        umock_c_deinit();
    }

    CTEST_FUNCTION_INITIALIZE()
    {
        umock_c_reset_all_calls();
    }

    CTEST_FUNCTION_CLEANUP()
    {
    }

    CTEST_FUNCTION(crypto_des_encrypt_input_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_encrypt(NULL, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_encrypt_output_NULL_fail)
    {
        // arrange

        // act
        int result = crypto_des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, NULL, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_encrypt_key_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, NULL, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_encrypt_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_encrypt_no_initial_vector_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, NULL, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_NO_INIT_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_decrypt_cipher_text_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_decrypt(NULL, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_decrypt_output_NULL_fail)
    {
        // arrange

        // act
        int result = crypto_des_decrypt(TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, NULL, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_decrypt_key_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_decrypt(TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, NULL, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_decrypt_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_decrypt(TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_des_decrypt_initial_vector_NULL_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_des_decrypt(TEST_NO_INIT_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_KEY_DATA, NULL, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    // 3 DES
    CTEST_FUNCTION(crypto_3des_encrypt_input_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_encrypt(NULL, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_encrypt_output_NULL_fail)
    {
        // arrange

        // act
        int result = crypto_3des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, NULL, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_encrypt_key_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, NULL, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_encrypt_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_IS_NOT_NULL(output);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_3DES_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_encrypt_no_initial_vector_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_encrypt(TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, NULL, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_3DES_NO_INIT_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_decrypt_cipher_text_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_decrypt(NULL, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_decrypt_output_NULL_fail)
    {
        // arrange

        // act
        int result = crypto_3des_decrypt(TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, NULL, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_decrypt_key_NULL_fail)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_decrypt(TEST_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, NULL, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_decrypt_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_decrypt(TEST_3DES_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, TEST_INITIAL_VECTOR, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(crypto_3des_decrypt_initial_vector_NULL_succeed)
    {
        // arrange
        unsigned char output[TEST_ENCRYPT_DATA_LEN];

        // act
        int result = crypto_3des_decrypt(TEST_3DES_NO_INIT_CIPHER_DATA, TEST_ENCRYPT_DATA_LEN, output, TEST_ENCRYPT_DATA_LEN, TEST_3DES_KEY_DATA, NULL, false);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 0, memcmp(output, TEST_ENCRYPT_DATA, TEST_ENCRYPT_DATA_LEN));
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

CTEST_END_TEST_SUITE(crypto_des_ut)

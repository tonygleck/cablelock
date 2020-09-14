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

#include <limits.h>

static void* my_mem_shim_malloc(size_t size)
{
    return malloc(size);
}

static void* my_mem_shim_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

static void* my_mem_shim_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
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

#include "cablelock/big_integer.h"

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(big_integer_ut)

    CTEST_SUITE_INITIALIZE()
    {
        int result;

        (void)umock_c_init(on_umock_c_error);

        REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(mem_shim_calloc, my_mem_shim_calloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_calloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(mem_shim_realloc, my_mem_shim_realloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_realloc, NULL);
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

    static void setup_multipy_mocks(void)
    {
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    }

    CTEST_FUNCTION(big_int_init_success)
    {
        // arrange
        BIG_INTEGER op_value;

        // act
        big_int_init(&op_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, op_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op_value);
    }

    CTEST_FUNCTION(big_int_init_input_op_NULL_fail)
    {
        // arrange

        // act
        big_int_init(NULL);

        // assert
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_assign_op_NULL_fail)
    {
        // arrange

        // act
        int result = big_int_assign(NULL, 1);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_assign_success)
    {
        // arrange
        BIG_INTEGER op_value;

        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));

        // act
        int result = big_int_assign(&op_value, 1);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, op_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op_value);
    }

    CTEST_FUNCTION(big_int_assign_fail)
    {
        // arrange
        BIG_INTEGER op_value;

        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG)).SetReturn(NULL);

        // act
        int result = big_int_assign(&op_value, 1);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op_value);
    }

    CTEST_FUNCTION(big_int_compare_op1_NULL_fail)
    {
        // arrange
        BIG_INTEGER op2_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(NULL, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_NOT_EQUAL(int, -1, result);
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_compare_op2_NULL_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, NULL);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_NOT_EQUAL(int, -1, result);
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_compare_op1_is_less_1_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 100));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 200));
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, -1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_compare_op1_is_less_2_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 200));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, UINT_MAX));
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, -1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_compare_op1_is_greater_1_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 200));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 100));
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_compare_op1_is_greater_2_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, UINT_MAX));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 200));
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 1, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_compare_values_are_equal_1_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 200));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 200));
        umock_c_reset_all_calls();

        // act
        int result = big_int_compare(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_add_op1_NULL_fail)
    {
        // arrange
        BIG_INTEGER op2_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_add(NULL, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_add_op2_NULL_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_add(&op1_value, NULL);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_add_expand_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 32768));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 32768));
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));

        // act
        int result = big_int_add(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 3, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 1, op1_value.data[0]); // 65536
        CTEST_ASSERT_ARE_EQUAL(int, 0, op1_value.data[1]);
        CTEST_ASSERT_ARE_EQUAL(int, 0, op1_value.data[2]);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_add_expand_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 32768));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 32768));
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG)).SetReturn(NULL);
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));

        // act
        int result = big_int_add(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }


    CTEST_FUNCTION(big_int_add_no_expand_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 32368));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 400));
        umock_c_reset_all_calls();

        // act
        int result = big_int_add(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 2, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 128, op1_value.data[0]); // 32768
        CTEST_ASSERT_ARE_EQUAL(int, 0, op1_value.data[1]);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_subtract_op1_NULL_fail)
    {
        // arrange
        BIG_INTEGER op2_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_subtract(NULL, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_subtract_op2_NULL_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_subtract(&op1_value, NULL);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_subtract_no_contract_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 33024));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 32768));
        umock_c_reset_all_calls();

        // act
        int result = big_int_subtract(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 2, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 1, op1_value.data[0]); // 256
        CTEST_ASSERT_ARE_EQUAL(int, 0, op1_value.data[1]);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_subtract_contract_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 32896));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 32768));
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));
        STRICT_EXPECTED_CALL(free(IGNORED_ARG));

        // act
        int result = big_int_subtract(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 1, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 128, op1_value.data[0]); // 128
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_multipy_op1_NULL_fail)
    {
        // arrange
        BIG_INTEGER op2_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_multipy(NULL, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_multipy_op2_NULL_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_multipy(&op1_value, NULL);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_multipy_op1_NULL_success)
    {
        // arrange
        BIG_INTEGER op2_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_multipy(NULL, &op2_value);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_multipy_op2_NULL_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        umock_c_reset_all_calls();

        // act
        int result = big_int_multipy(&op1_value, NULL);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    CTEST_FUNCTION(big_int_multipy_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 256));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 128));
        umock_c_reset_all_calls();

        setup_multipy_mocks();

        // act
        int result = big_int_multipy(&op1_value, &op2_value);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 2, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 128, op1_value.data[0]); // 32768
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_multipy_fail)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER op2_value;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 256));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op2_value, 128));
        umock_c_reset_all_calls();

        int negativeTestsInitResult = umock_c_negative_tests_init();
        CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        setup_multipy_mocks();

        // act
        umock_c_negative_tests_snapshot();

        size_t count = umock_c_negative_tests_call_count();
        for (size_t index = 0; index < count; index++)
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            int result = big_int_multipy(&op1_value, &op2_value);

            // assert
            CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        }

        // cleanup
        umock_c_negative_tests_deinit();
        big_int_deinit(&op1_value);
        big_int_deinit(&op2_value);
    }

    CTEST_FUNCTION(big_int_divide_dividend_NULL_fail)
    {
        // arrange
        BIG_INTEGER divisor;
        BIG_INTEGER quotient = {0};
        umock_c_reset_all_calls();

        // act
        int result = big_int_divide(NULL, &divisor, &quotient);

        // assert
        CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
    }

    // CTEST_FUNCTION(big_int_divide_success)
    // {
    //     // arrange
    //     BIG_INTEGER dividend;
    //     BIG_INTEGER divisor;
    //     BIG_INTEGER quotient = {0};
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&dividend, 128));
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&divisor, 2));
    //     umock_c_reset_all_calls();

    //     STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));

    //     // act
    //     int result = big_int_divide(&dividend, &divisor, &quotient);

    //     // assert
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    //     CTEST_ASSERT_ARE_EQUAL(int, 1, quotient.data_len);
    //     CTEST_ASSERT_ARE_EQUAL(int, 64, quotient.data[0]);
    //     CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //     // cleanup
    //     big_int_deinit(&dividend);
    //     big_int_deinit(&divisor);
    //     big_int_deinit(&quotient);
    // }

    // CTEST_FUNCTION(big_int_divide_1_success)
    // {
    //     // arrange
    //     BIG_INTEGER dividend;
    //     BIG_INTEGER divisor;
    //     BIG_INTEGER quotient = {0};
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&dividend, 524288));
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&divisor, 256));
    //     umock_c_reset_all_calls();

    //     STRICT_EXPECTED_CALL(calloc(IGNORED_ARG, IGNORED_ARG));

    //     // act
    //     int result = big_int_divide(&dividend, &divisor, &quotient);

    //     // assert
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    //     CTEST_ASSERT_ARE_EQUAL(int, 2, quotient.data_len);
    //     CTEST_ASSERT_ARE_EQUAL(int, 0, quotient.data[0]);
    //     CTEST_ASSERT_ARE_EQUAL(int, 8, quotient.data[1]);
    //     CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //     // cleanup
    //     big_int_deinit(&dividend);
    //     big_int_deinit(&divisor);
    //     big_int_deinit(&quotient);
    // }

    CTEST_FUNCTION(big_int_exponentiate_success)
    {
        // arrange
        BIG_INTEGER op1_value;
        BIG_INTEGER exp;
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&op1_value, 64));
        CTEST_ASSERT_ARE_EQUAL(int, 0, big_int_assign(&exp, 2));
        umock_c_reset_all_calls();

        // act
        int result = big_int_exponentiate(&op1_value, &exp);

        // assert
        CTEST_ASSERT_ARE_EQUAL(int, 0, result);
        CTEST_ASSERT_ARE_EQUAL(int, 2, op1_value.data_len);
        CTEST_ASSERT_ARE_EQUAL(int, 8, op1_value.data[0]); // 4096
        CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        // cleanup
        big_int_deinit(&op1_value);
        big_int_deinit(&exp);
    }

CTEST_END_TEST_SUITE(big_integer_ut)

// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifdef __cplusplus
extern "C" {
    #include <cstdlib>
#else
    #include <stdlib.h>
#endif

#include "umock_c/umock_c_prod.h"

// OPTIMIZATION: Create an alloc size and an actual size
// So you will never have to shrink the value only expand
typedef struct BIG_INTEGER_INFO_TAG
{
    size_t data_len;
    // Each data character represents up to 256 values
    unsigned char* data;
} BIG_INTEGER;

MOCKABLE_FUNCTION(, void, big_int_init, BIG_INTEGER*, op);
MOCKABLE_FUNCTION(, void, big_int_deinit, BIG_INTEGER*, op);

MOCKABLE_FUNCTION(, int, big_int_assign, BIG_INTEGER*, op, unsigned int, value);

/**
* @brief    Compares two big integers to on another
*
* @param    op1     Initial operand 1
* @param    op2     Operand 2
*
* @return   An integer indicating which value is greater
*           0 if op1 == op2
*           -1 if op1 is greater
*           1 if op2 is greater
*/
MOCKABLE_FUNCTION(, int, big_int_compare, const BIG_INTEGER*, op1, const BIG_INTEGER*, op2);
MOCKABLE_FUNCTION(, int, big_int_to_string, const BIG_INTEGER*, op1, char*, result, size_t*, length);

MOCKABLE_FUNCTION(, int, big_int_add, BIG_INTEGER*, op1, BIG_INTEGER*, op2);
MOCKABLE_FUNCTION(, int, big_int_subtract, BIG_INTEGER*, op1, BIG_INTEGER*, op2);
MOCKABLE_FUNCTION(, int, big_int_multipy, BIG_INTEGER*, op1, BIG_INTEGER*, op2);

/**
* @brief    Divides the dividend byt the divisor to get the quotient
*
* @param    dividend    The number to be divided into with the return being the remainder
* @param    divisor     The number which divides the other number
* @param    quotient    The result value of the operation
*
* @return   An integer indicating success 0 is success non-zero failure
*/
MOCKABLE_FUNCTION(, int, big_int_divide, BIG_INTEGER*, dividend, BIG_INTEGER*, divisor, BIG_INTEGER*, quotient);

MOCKABLE_FUNCTION(, int, big_int_exponentiate, BIG_INTEGER*, op1, const BIG_INTEGER*, exp);

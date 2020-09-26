// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"

#include "cablelock/big_integer.h"

static void print_bits(char* ty, char* val, const unsigned char* bytes, size_t num_bytes)
{
    printf("(%*s) %*s = [ ", 15, ty, 16, val);
    for (size_t index = 0; index < num_bytes; index++)
    {
        for (int inner = 7; 0 <= inner; inner--)
        {
            printf("%c", (bytes[index] & (1 << inner) ? '1' : '0'));
        }
        printf(" ");
    }
    printf("]\n");
}

#define SHOW_BITS(T,V) do { T x = V; print_bits(#T, #V, (unsigned char*) &x, sizeof(x)); } while(0)

static int allocate_big_int(BIG_INTEGER* value, size_t length)
{
    int result;
    if ((value->data = (unsigned char*)calloc(length, sizeof(unsigned char))) == NULL)
    {
        log_error("Failure allocating integer data");
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

// Expand the space for operation by 1 char and set the LSB of that int to 1
static int expand(BIG_INTEGER* value)
{
    int result;
    unsigned char* temp = value->data;
    value->data_len++;
    if (allocate_big_int(value, value->data_len) != 0)
    {
        log_error("Failure allocating integer data");
        result = __LINE__;
    }
    else
    {
        memcpy(value->data + 1, temp, (value->data_len-1) * sizeof(unsigned char));
        value->data[0] = 0x01;
        free(temp);
        result = 0;
    }
    return result;
}

static int contract(BIG_INTEGER* op)
{
    int result = 0;
    size_t index = 0;
    while (!(op->data[index]) && (index < op->data_len)) { index++; }

    if (index && index < op->data_len)
    {
        unsigned char* temp = op->data;
        // Reduce the memory allocated for the contraction
        if (allocate_big_int(op, op->data_len - index) != 0)
        {
            log_error("Failure allocating integer data");
            result = __LINE__;
        }
        else
        {
            memcpy(op->data, temp+index, op->data_len - index);
            op->data_len -= index;
            free(temp);
        }
    }
    return result;
}

static int copy_value(BIG_INTEGER* dest, BIG_INTEGER* src)
{
    int result;
    if (dest->data != NULL)
    {
        free(dest->data);
    }
    dest->data_len = src->data_len;
    if (allocate_big_int(dest, dest->data_len) != 0)
    {
        log_error("Failure allocating integer data");
        result = __LINE__;
    }
    else
    {
        memcpy(dest->data, src->data, dest->data_len*sizeof(unsigned char));
        result = 0;
    }
    return result;
}

static int right_shift(BIG_INTEGER* value)
{
    size_t index = 0;
    int prev_carry = 0;
    int carry = 0;

    do
    {
        prev_carry = carry;
        carry = (value->data[index] >> 0x01) << 7;
        value->data[index] = (value->data[index] >> 1) | prev_carry;
    } while (++index < value->data_len);
    return contract(value);
}

static int left_shift(BIG_INTEGER* value)
{
    int result = 0;
    size_t index = value->data_len;
    int prev_carry = 0;
    int carry = 0;
    do
    {
        index--;
        prev_carry = carry;
        carry = (value->data[index] & 0x80) == 0x80;
        value->data[index] = (value->data[index] << 1) | prev_carry;
    } while (index);
    if (carry)
    {
        result = expand(value);
    }
    return result;
}

static int set_value(BIG_INTEGER* op, unsigned int value)
{
    int result;
    unsigned int mask;
    unsigned int shift;
    op->data_len = 4;
    for (mask = 0xFF000000; mask > 0x000000FF; mask >>= 8)
    {
        if (value & mask)
        {
            break;
        }
        op->data_len--;
    }

    if (allocate_big_int(op, op->data_len) != 0)
    {
        log_error("Failure allocating integer data");
        result = __LINE__;
    }
    else
    {
        mask = 0x000000FF;
        shift = 0;
        for (size_t index = op->data_len; index; index--)
        {
            op->data[index-1] = (value & mask) >> shift;
            mask <<= 8;
            shift += 8;
        }
        result = 0;
    }
    return result;
}

static int compare_value(const BIG_INTEGER* op1, const BIG_INTEGER* op2)
{
    int result = 0;
    if (op1->data_len > op2->data_len)
    {
        result = 1;
    }
    else if (op1->data_len < op2->data_len)
    {
        result = -1;
    }
    else
    {
        // Need to compare the hi-int since the lower ints cant' change
        // the comparison
        // Keep searching through the representational int until one is
        // bigger than the other
        size_t index = 0;
        while (index < op1->data_len && index < op2->data_len)
        {
            if (op1->data[index] < op2->data[index])
            {
                result = -1;
                break;
            }
            else if (op1->data[index] > op2->data[index])
            {
                result = 1;
                break;
            }
            index++;
        }
    }
    return result;
}

static int add_operation(BIG_INTEGER* op1, BIG_INTEGER* op2)
{
    int result = 0;

    unsigned int sum;
    unsigned int carry = 0;
    if (op2->data_len > op1->data_len)
    {
        unsigned char* temp = op1->data;
        if (allocate_big_int(op1, op2->data_len) != 0)
        {
            log_error("Failure allocating integer data");
            result = __LINE__;
        }
        else
        {
            memcpy(op1->data + (op2->data_len - op1->data_len), temp, op1->data_len);
            op1->data_len = op2->data_len;
            free(temp);
        }
    }
    if (result == 0)
    {
        unsigned int index1 = op1->data_len;
        unsigned int index2 = op2->data_len;
        do
        {
            index1--;
            if (index2)
            {
                index2--;
                sum = op1->data[index1] + op2->data[index2] + carry;
            }
            else
            {
                sum = op1->data[index1] + carry;
            }
            carry = sum > 0xFF;
            op1->data[index1] = sum;
        } while (index1);
        if (carry)
        {
            if (expand(op1) != 0)
            {
                result = __LINE__;
                free(op1->data);
            }
        }
    }
    return result;
}

static int subtract_operation(BIG_INTEGER* op1, BIG_INTEGER* op2)
{
    int result = 0;
    int difference;
    unsigned int borrow = 0;
    int index1 = op1->data_len;
    int index2 = op2->data_len;
    do
    {
        index1--;
        if (index2)
        {
            index2--;
            difference = op1->data[index1] - op2->data[index2] - borrow;
        }
        else
        {
            difference = op1->data[index1] - borrow;
        }
        borrow = (difference < 0);
        op1->data[index1] = difference;
    } while (index1);

    if (borrow && index1)
    {
        if (!(op1->data[index1 - 1])) // We don't borrow from a 1
        {
            log_error("Invalid subtraction results in negative number");
            result = __LINE__;
        }
        op1->data[index1 - 1]--;
    }
    if (result == 0)
    {
        result = contract(op1);
    }
    return result;
}

static int multiply_operation(BIG_INTEGER* op1, const BIG_INTEGER* op2)
{
    int result;
    BIG_INTEGER temp = {0};
    if (copy_value(&temp, op1) != 0)
    {
        log_error("Failure copying result value");
        result = __LINE__;
    }
    else
    {
        result = 0;
        free(op1->data);
        set_value(op1, 0);
        size_t index = op2->data_len;
        do
        {
            index--;
            for (size_t mask = 0x01; mask; mask <<= 1)
            {
                if (mask & op2->data[index])
                {
                    if ((result = add_operation(op1, &temp)) != 0)
                    {
                        log_error("Failure adding in multiply operation");
                        break;
                    }
                }
                result = left_shift(&temp);
            }
        } while (index && result == 0);
        free(temp.data);
    }
    return result;
}

void big_int_init(BIG_INTEGER* op)
{
    if (op != NULL)
    {
        memset(op, 0, sizeof(BIG_INTEGER));
    }
}

void big_int_deinit(BIG_INTEGER* op)
{
    if (op != NULL)
    {
        free(op->data);
        memset(op, 0, sizeof(BIG_INTEGER));
    }
}

int big_int_assign(BIG_INTEGER* op, unsigned int value)
{
    int result;
    if (op == NULL)
    {
        log_error("Invalid value specified");
        result = __LINE__;
    }
    else
    {
        result = set_value(op, value);
    }
    return result;
}

int big_int_compare(const BIG_INTEGER* op1, const BIG_INTEGER* op2)
{
    int result;
    if (op1 == NULL || op2 == NULL)
    {
        log_error("Invalid value specified op1: %p, op2: %p", op1, op2);
        result = __LINE__;
    }
    else
    {
        result = compare_value(op1, op2);
    }
    return result;
}

int big_int_to_string(const BIG_INTEGER* op, char* string, size_t* length)
{
    (void)string;
    int result;
    if (op == NULL || length == NULL)
    {
        result = __LINE__;
    }
    else
    {
        // Get past the leading zeros
        size_t pos = 0;
        while (op->data[pos] == '0')
        {
            pos++;
        }
        size_t needed_len = op->data_len - pos;
        result = 0;
    }
    return result;
}

int big_int_add(BIG_INTEGER* op1, BIG_INTEGER* op2)
{
    int result = 0;
    if (op1 == NULL || op2 == NULL)
    {
        log_error("Invalid value specified op1: %p, op2: %p", op1, op2);
        result = __LINE__;
    }
    else
    {
        result = add_operation(op1, op2);
    }
    return result;
}

int big_int_subtract(BIG_INTEGER* op1, BIG_INTEGER* op2)
{
    int result = 0;
    if (op1 == NULL || op2 == NULL)
    {
        log_error("Invalid value specified op1: %p, op2: %p", op1, op2);
        result = __LINE__;
    }
    else
    {
        result = subtract_operation(op1, op2);
    }
    return result;
}

int big_int_multipy(BIG_INTEGER* op1, BIG_INTEGER* op2)
{
    int result = 0;
    if (op1 == NULL || op2 == NULL)
    {
        log_error("Invalid value specified op1: %p, op2: %p", op1, op2);
        result = __LINE__;
    }
    else
    {
        result = multiply_operation(op1, op2);
    }
    return result;
}

// TODO: Fix Divide
int big_int_divide(BIG_INTEGER* dividend, BIG_INTEGER* divisor, BIG_INTEGER* quotient)
{
    (void)quotient;
    int result = __LINE__;
    BIG_INTEGER temp = {0};
    if (dividend == NULL || divisor == NULL)
    {
        log_error("Invalid value specified dividend: %p, divisor: %p", dividend, divisor);
        result = __LINE__;
    }
/*    else
    {
        int bit_size = 0;
        int bit_position = 0;

        // Left shift divisor until it's >= the dividend
        while (compare_value(divisor, dividend) < 0)
        {
            if (left_shift(divisor) != 0)
            {
                result = __LINE__;
                break;
            }
            bit_size++;
        }
        if (result == 0)
        {
            if (quotient != NULL)
            {
                quotient->data_len = (bit_size / 8) + 1;
                if (allocate_big_int(quotient, quotient->data_len) != 0)
                {
                    log_error("Failure allocating quotient");
                    result = __LINE__;
                }
            }

            if (result == 0)
            {
                bit_position = 8 - (bit_size % 8) - 1;
                do
                {
                    if (compare_value(divisor, dividend) <= 0)
                    {
                        if (subtract_operation(dividend, divisor) != 0)
                        {
                            log_error("Failure subtracting dividend from divisor");
                            result = __LINE__;
                            break;
                        }
                        else
                        {
                            if (quotient != NULL)
                            {
                                quotient->data[(int)(bit_position/8)] |= (0x80 >> (bit_position % 8));
                            }
                        }
                    }
                    if (bit_size)
                    {
                        if (right_shift(divisor) != 0)
                        {
                            log_error("Failure in right shift operation");
                            result = __LINE__;
                            break;
                        }
                    }
                    bit_position++;
                } while (bit_size--);
            }
        }
    }*/
    return result;
}

// TODO: Fix exponentiate
int big_int_exponentiate(BIG_INTEGER* op, const BIG_INTEGER* exp)
{
    int result;
    BIG_INTEGER temp1 = {0};
    if (op == NULL || exp == NULL)
    {
        log_error("Invalid value specified op: %p, exp: %p", op, exp);
        result = __LINE__;
    }
    /*else if (copy_value(&temp1, op) != 0 || set_value(op, 1) != 0)
    {
        log_error("Failure copying result value");
        result = __LINE__;
    }
    else
    {
        result = 0;
        size_t index = exp->data_len;
        BIG_INTEGER temp2 = {0};
        do
        {
            index--;
            size_t count = 0;
            for (size_t mask = 0x01; mask; mask <<= 1)
            {
                char val[128];
                sprintf(val, "%lu", mask);
                //SHOW_BITS(unsigned int, val);
                print_bits("unsigned int", val, (const unsigned char*)&mask, sizeof(mask));
                if (exp->data[index] & mask)
                {
                    if ((result = multiply_operation(op, &temp1)) != 0)
                    {
                        log_error("Failure copying result value");
                        break;
                    }
                    // Square temp2
                    if (copy_value(&temp2, &temp1) != 0)
                    {
                        log_error("Failure copying result value");
                        result = __LINE__;
                        break;
                    }
                    else if (multiply_operation(&temp1, &temp2) != 0)
                    {
                        log_error("Failure copying result value");
                        result = __LINE__;
                        break;
                    }
                }
                count++;
            }
        } while (index && result == 0);
        free(temp1.data);
        free(temp2.data);
    }*/
    return result;
}
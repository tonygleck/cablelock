#ifndef _CRYPTO_MACRO_H
#define _CRYPTO_MACRO_H

// Bit manipulation macros
#define GET_BIT(target, val) (target[(int)(val / 8)] & (0x80 >> (val % 8)))
#define SET_BIT(target, val) (target[(int)(val / 8)] |= (0x80 >> (val % 8)))
#define CLEAR_BIT(target, val) (target[(int)(val / 8)] &= ~(0x80 >> (val % 8)))

// Overwrite target array with the XOR of the src array
static void xor_value(unsigned char* target, const unsigned char* src, size_t length)
{
    while (length--)
    {
        *target++ ^= *src++;
    }
}

#endif // _CRYPTO_MACRO_H
#ifndef _CRYPTO_MACRO_H
#define _CRYPTO_MACRO_H

// Bit manipulation macros
#define GET_BIT(target, val) (target[(int)(val / 8)] & (0x80 >> (val % 8)))
#define SET_BIT(target, val) (target[(int)(val / 8)] |= (0x80 >> (val % 8)))
#define CLEAR_BIT(target, val) (target[(int)(val / 8)] &= ~(0x80 >> (val % 8)))


#endif // _CRYPTO_MACRO_H
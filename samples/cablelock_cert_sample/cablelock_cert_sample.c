#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cablelock/crypto_certificate.h"

#include "huge.h"

static const char* CERT_FILEPATH = "/home/jebrando/development/repo/personal/cablelock/test_cert/rsa_x509.der";
//static const char* CERT_FILEPATH = "/home/jebrando/development/repo/personal/cablelock/test_cert/rsa_x509.pem";
static const char* KEY_FILEPATH = NULL;

static void printout_bites(const char* text, unsigned char* data, size_t data_len)
{
    printf("%s", text);
    while(data_len--)
    {
        printf("0x%.02x, ", *data++);
    }
    printf("\r\n");
}

int main(int argc, char* argv[])
{
    int result;
    bool use_padding = false;

    huge dividend;
    set_huge(&dividend, 524288);
    huge divisor;
    set_huge(&divisor, 256);
    huge quotient;
    divide(&dividend, &divisor, &quotient);

    if (quotient.size == 1)
    {
        printf("quotient value is correct");
    }

    //CERTIFIATE_INFO_HANDLE cert_handle = crypto_cert_load(CERT_FILEPATH, KEY_FILEPATH);
    //if (cert_handle != NULL)
    //{
    //    crypto_cert_destroy(cert_handle);
    //}
    return 0;
}

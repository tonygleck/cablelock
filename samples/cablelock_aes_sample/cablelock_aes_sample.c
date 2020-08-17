#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cablelock/crypto_ciphers.h"

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
    //unsigned char* key = "password";
    unsigned char* key = "twentyfourcharacterinput";
    unsigned char* init_vector = NULL;//"initialz";
    unsigned char* input = "abcdefghijklmnop";
    unsigned char* output;
    unsigned char* check_data;

    size_t out_len, input_len, check_len;
    check_len = out_len = input_len = strlen(input);
    if ((output = (unsigned char*)malloc(out_len)) == NULL)
    {
        printf("Failed to allocate output\r\n");
    }
    else if ((check_data = (unsigned char*)malloc(out_len)) == NULL)
    {
        printf("Failed to allocate check data\r\n");
        free(output);
    }
    else
    {
        if (crypto_3des_encrypt(input, input_len, output, out_len, key, init_vector, use_padding) != 0)
        {
            printf("Failure encrypting payload\r\n");
        }
        else
        {
            printf("Initial data: %s\r\n", input);
            printout_bites("Output data: ", output, out_len);
            if (crypto_3des_decrypt(output, out_len, check_data, check_len, key, init_vector, use_padding) )
            {
                printf("Failure decrypting payload\r\n");
            }
            else
            {
                if (memcmp(input, check_data, input_len) != 0)
                {
                    printf("Encryption/Decryption did not work\n");
                }
                else
                {
                    printout_bites("Successfully Decrypted Data ", check_data, check_len);
                }
                result = 0;
            }
        }
        free(check_data);
        free(output);
    }
    return 0;
}

// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdbool.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"
#include "lib-util-c/binary_encoder.h"

#include "cablelock/crypto_certificate.h"
#include "cablelock/crypto_cert_properties.h"

static const char* PEM_HEADER_FRAG = "-----BEGIN";
#define PEM_HEADER_FRAG_LEN     10

typedef struct CERTIFIATE_INFO_TAG
{
    bool file_loaded;
    const unsigned char* certificate;
    size_t cert_len;
    const void* private_key;
} CERTIFIATE_INFO;

static unsigned char* extract_der_from_cert(const unsigned char* cert_format, size_t length)
{
    unsigned char* result;
    // Check for PEM format
    if (memcmp(cert_format, PEM_HEADER_FRAG, PEM_HEADER_FRAG_LEN) == 0)
    {
        size_t result_len = 0;
        const unsigned char* begin_pos = cert_format;
        const unsigned char* end_pos = cert_format + length;
        while (*begin_pos != '\n')
        {
            begin_pos++;
            length--;
        }
        // Go past the \n
        begin_pos++;
        bool cont_loop = true;
        while (true)
        {
            if (*end_pos == '\n')
            {
                if (!cont_loop)
                {
                    break;
                }
                cont_loop = false;
            }
            length--;
            end_pos--;
        }
        // Go past the \n
        end_pos--;
        size_t cert_len = end_pos-begin_pos;
        if (bin_encoder_64_decode_partial((const char*)begin_pos, cert_len, NULL, &result_len) != -1)
        {
            log_error("Failure encoding base64 certificate");
            result = NULL;
        }
        else if ((result = malloc(result_len)) == NULL)
        {
            log_error("Failure allocating data for certificate");
        }
        else if (bin_encoder_64_decode_partial((const char*)begin_pos, cert_len, result, &result_len) != 0)
        {
            log_error("Failure allocating data");
            free(result);
            result = NULL;
        }
        else
        {
        }
    }
    else
    {
        if ((result = malloc(length)) == NULL)
        {
            log_error("Failure allocating data");
            result = NULL;
        }
        else
        {
            memcpy(result, cert_format, length);
        }
    }
    return result;
}

static int parse_certificate(CERTIFIATE_INFO* cert_info)
{
    int result;
    // base64 decode certificate
    unsigned char* der_cert = extract_der_from_cert(cert_info->certificate, cert_info->cert_len);
    if (der_cert == NULL)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

static unsigned char* read_file_item(const char* file_path, size_t* length)
{
    unsigned char* result;
    FILE* file_item;
    if ((file_item = fopen(file_path, "rb")) == NULL)
    {
        log_error("Failure opening cert file %s", file_path);
        result = NULL;
    }
    else
    {
        size_t file_len;
        // Get the size of the file
        fseek(file_item, 0, SEEK_END);
        file_len = ftell(file_item);
        fseek(file_item, 0, SEEK_SET);
        if ((result = malloc(sizeof(file_len) ) ) == NULL)
        {
            log_error("Failure allocating file");
        }
        else if (fread(result, 1, file_len, file_item) != file_len)
        {
            log_error("Failure reading file");
            free(result);
            result = NULL;
        }
        else
        {
            if (length != NULL)
            {
                *length = file_len;
            }
        }
        fclose(file_item);
    }
    return result;
}

CERTIFIATE_INFO_HANDLE crypto_cert_load(const char* certificate_path, const char* private_key_path)
{
    CERTIFIATE_INFO* result;
    if (certificate_path == NULL)
    {
        log_error("Invalid parameter specified certificate_path: %p", certificate_path);
        result = NULL;
    }
    else if ((result = malloc(sizeof(CERTIFIATE_INFO))) == NULL)
    {
        log_error("Failure allocating certificate info");
    }
    else
    {
        result->file_loaded = true;
        if ((result->certificate = read_file_item(certificate_path, &result->cert_len)) == NULL)
        {
            log_error("Failure opening certificate: %s", certificate_path);
            result = NULL;
        }
        else if (private_key_path != NULL && (result->private_key = read_file_item(private_key_path, NULL)) == NULL)
        {
            log_error("Failure opening key file %s", private_key_path);
            free((char*)result->certificate);
            result = NULL;
        }
        else if (parse_certificate(result) != 0)
        {
            log_error("Failure parsing certificate");
            free((char*)result->certificate);
            free((char*)result->private_key);
            free(result);
            result = NULL;
        }
    }
    return result;
}

CERTIFIATE_INFO_HANDLE crypto_cert_create(const unsigned char* certificate, const void* private_key)
{
    CERTIFIATE_INFO* result = NULL;
    if (certificate == NULL)
    {
        log_error("Invalid parameter specified certificate: %p", certificate);
        result = NULL;
    }
    else if ((result = malloc(sizeof(CERTIFIATE_INFO))) == NULL)
    {
        log_error("Failure allocating certificate info");
    }
    else
    {
        result->file_loaded = false;
        result->certificate = certificate;
        result->private_key = private_key;
        if (parse_certificate(result) != 0)
        {
            log_error("Failure parsing certificate");
            free(result);
            result = NULL;
        }
    }
    return result;
}

void crypto_cert_destroy(CERTIFIATE_INFO_HANDLE handle)
{
    if (handle != NULL)
    {
        if (handle->file_loaded)
        {
            free((char*)handle->certificate);
            free((char*)handle->private_key);
        }
        free(handle);
    }
}

bool crypto_cert_is_expired(CERTIFIATE_INFO_HANDLE handle)
{
    bool result;
    if (handle == NULL)
    {
        result = false;
    }
    else
    {
        result = true;
    }
    return result;
}

//CERT_PROPERTIES_HANDLE crypto_cert_get_properties(CERTIFIATE_INFO_HANDLE handle)
//{
//    return NULL;
//}

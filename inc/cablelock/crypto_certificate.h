// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifdef __cplusplus
extern "C" {
    #include <cstdlib>
#else
    #include <stdlib.h>
    #include <stdbool.h>
#endif

#include "umock_c/umock_c_prod.h"

//#include "crypto_cert_properties.h"

typedef struct CERTIFIATE_INFO_TAG* CERTIFIATE_INFO_HANDLE;

MOCKABLE_FUNCTION(, CERTIFIATE_INFO_HANDLE, crypto_cert_load, const char*, certificate_path, const char*, private_key_path);
MOCKABLE_FUNCTION(, CERTIFIATE_INFO_HANDLE, crypto_cert_create, const unsigned char*, certificate, const void*, private_key);

MOCKABLE_FUNCTION(, void, crypto_cert_destroy, CERTIFIATE_INFO_HANDLE, handle);

MOCKABLE_FUNCTION(, bool, crypto_cert_is_expired, CERTIFIATE_INFO_HANDLE, handle);

//MOCKABLE_FUNCTION(, CERT_PROPERTIES_HANDLE, crypto_cert_get_properties, CERTIFIATE_INFO_HANDLE, handle);

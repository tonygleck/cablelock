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

typedef struct CERT_PROP_TAG* CERT_PROPERTIES_HANDLE;

MOCKABLE_FUNCTION(, CERT_PROPERTIES_HANDLE, cert_get_properties, CERTIFIATE_INFO_HANDLE, handle);
MOCKABLE_FUNCTION(, int64_t, certificate_info_get_valid_from, CERTIFIATE_INFO_HANDLE, handle);
MOCKABLE_FUNCTION(, int64_t, certificate_info_get_valid_to, CERTIFIATE_INFO_HANDLE, handle);
MOCKABLE_FUNCTION(, const char*, certificate_info_get_issuer, CERTIFIATE_INFO_HANDLE, handle);

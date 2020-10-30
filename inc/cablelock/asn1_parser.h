// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifdef __cplusplus
extern "C" {
    #include <cstdlib>
#else
    #include <stdlib.h>
#endif

#include "umock_c/umock_c_prod.h"

typedef struct ASN_PARSER_INFO_TAG* ASN1_INFO_HANDLE;

MOCKABLE_FUNCTION(, ASN1_INFO_HANDLE, asn1_parse_data, const unsigned char*, buffer, size_t, length);
MOCKABLE_FUNCTION(, void, asn1_free, ASN1_INFO_HANDLE, handle);

MOCKABLE_FUNCTION(, void, asn1_display, ASN1_INFO_HANDLE, handle);

// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdbool.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"

#include "cablelock/asn1_parser.h"

typedef struct ASN_PARSER_INFO_TAG
{
    int constructed;
    int tag_class;
    int tag;
    size_t length;
    const unsigned char* data;
    struct ASN_PARSER_INFO_TAG* child;
    struct ASN_PARSER_INFO_TAG* next;
} ASN_PARSER_INFO;

int parse_asn1(ASN_PARSER_INFO* asn_info, const unsigned char* buffer, size_t length)
{
    int result;
    ASN_PARSER_INFO* token = asn_info;
    const unsigned char* ptr = buffer;
    const unsigned char* ptr_begin;
    unsigned int tag;
    unsigned long tag_length;
    unsigned char tag_length_byte;
    result = 0;
    while (length)
    {
        ptr_begin = ptr;
        tag = *ptr;
        ptr++;
        length--;

        // Check to see if this is a multi-byte tag (bits 5-1 all "1")
        if ((tag & 0x1F) == 0x1F)
        {
            // x.509 does not define then, so if we encounter it
            // we need to ignore it
            tag = 0;
            while (*ptr & 0x80)
            {
                tag <<= 8;
                tag |= *ptr & 0x7F;
            }
        }
        tag_length_byte = *ptr;
        ptr++;
        length--;

        if (tag_length_byte & 0x80)
        {
            const unsigned char* len_ptr = ptr;
            tag_length = 0;
            while ((len_ptr - ptr) < (tag_length_byte & 0x7F))
            {
                tag_length <<= 8;
                tag_length |= *(len_ptr++);
                length--;
            }
            ptr = len_ptr;
        }
        else
        {
            tag_length = tag_length_byte;
        }
        token->constructed = tag & 0x20;
        token->tag_class = (tag & 0xC0) >> 6;
        token->length = tag_length;
        token->data = ptr;
        token->child = token->next = NULL;
        if (tag & 0x20)
        {
            token->length = tag_length + (ptr - ptr_begin);
            token->data = ptr_begin;

            // Append the child to the tag and recurse into that child
            if ((token->child = (ASN_PARSER_INFO*)malloc(sizeof(ASN_PARSER_INFO))) == NULL)
            {
                log_error("Failure allocating token child");
                result = __LINE__;
                break;
            }
            else
            {
                if (parse_asn1(token->child, ptr, tag_length) != 0)
                {
                    log_error("Failure parsing asn1 data");
                    result = __LINE__;
                    break;
                }
                else
                {
                    ptr += tag_length;
                    length -= tag_length;

                    // This is the tag for the next token in the buffer
                    if (length)
                    {
                        if ((token->next = (ASN_PARSER_INFO*)malloc(sizeof(ASN_PARSER_INFO))) == NULL)
                        {
                            log_error("Failure allocating next token");
                            result = __LINE__;
                            break;
                        }
                        else
                        {
                            token = token->next;
                        }
                    }
                }
            }
        }
    }
    return result;
}

void asn1_free(ASN1_INFO_HANDLE handle)
{
    if (handle != NULL)
    {
        asn1_free(handle->child);
        free(handle->child);
        asn1_free(handle->next);
        free(handle->next);
        free(handle);
    }
}

ASN1_INFO_HANDLE asn1_parse_data(const unsigned char* buffer, size_t length)
{
    ASN_PARSER_INFO* result;
    if (buffer == NULL || length == 0)
    {
        log_error("Invalid parameter specified buffer: %p, length: %lu", buffer, length);
        result = NULL;
    }
    else if ((result = (ASN_PARSER_INFO*)malloc(sizeof(ASN_PARSER_INFO))) == NULL)
    {
        log_error("Failure allocating ASN.1 structure");
    }
    else if (parse_asn1(result, buffer, length) != 0)
    {
        log_error("Failure parsing ASN.1 information");
        asn1_free(result);
        result = NULL;
    }
    return result;
}

void asn1_display(ASN1_INFO_HANDLE handle)
{
    if (handle != NULL)
    {

    }
}
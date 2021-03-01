#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>

#include "mbedtls/oid.h"
#include "v2g/v2g_security.h"
#include "charger/charger.h"
#include "OpenV2G/xmldsig/xmldsigEXIDatatypes.h"
#include "OpenV2G/xmldsig/xmldsigEXIDatatypesEncoder.h"
#include "OpenV2G/codec/v2gEXIDatatypesEncoder.h"

size_t find_oid_value_in_name(const mbedtls_x509_name *name, const char* target_short_name, char *value, size_t value_length)
{
    const char* short_name = NULL;
    bool found = false;
    size_t retval = 0;

    while((name != NULL) && !found)
    {
        // if there is no data for this name go to the next one
        if(!name->oid.p)
        {
            name = name->next;
            continue;
        }

        int ret = mbedtls_oid_get_attr_short_name(&name->oid, &short_name);
        if((ret == 0) && (strcmp(short_name, target_short_name) == 0))
        {
            found = true;
        }

        if(found)
        {
            size_t bytes_to_write = (name->val.len >= value_length) ? value_length - 1 : name->val.len;

            for(size_t i = 0; i < bytes_to_write; i++)
            {
                char c = name->val.p[i];
                if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                {
                    value[i] = '?';
                } else
                {
                    value[i] = c;
                }
            }

            // null terminate
            value[bytes_to_write] = 0;

            retval = name->val.len;
        }

        name = name->next;
    }

    return retval;
}

int verify_v2g_signature(   struct v2gSignatureType *sig, 
                            struct v2gEXIFragment *auth_fragment,
                            mbedtls_ecdsa_context *ctx) {
    //struct v2gSignatureType *sig = &exiIn->V2G_Message.Header.Signature;
    unsigned char buf[1024];
    uint16_t buffer_pos = 0;
    struct v2gReferenceType *req_ref = &sig->SignedInfo.Reference.array[0];
    bitstream_t stream = {
        .size = 1024,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };
    uint8_t digest[32];
    int err;

    PRINTF("Verifying V2G Signature...\r\n");

    // Part 1 - Digest (hash)
    if ((err = encode_v2gExiFragment(&stream, auth_fragment)) != 0) {
        PRINTF("handle_authorization: unable to encode auth fragment\n");
        return 1;
    }
    mbedtls_sha256(buf, (size_t)buffer_pos, digest, 0);
    PRINTF("Signature bufferpos: %d\r\n", buffer_pos);
    PRINTF("Digest len: %d\r\n", req_ref->DigestValue.bytesLen);
    if (req_ref->DigestValue.bytesLen != 32 || 
        memcmp(req_ref->DigestValue.bytes, digest, 32) != 0) {
        PRINTF("handle_authorization: invalid digest\n");
        return 2;
    }

    // Part 2 - Content (xml signature + encryption)
    PRINTF("V2G SIG PART2\r\n");
    struct xmldsigEXIFragment sig_fragment;
    init_xmldsigEXIFragment(&sig_fragment);
    sig_fragment.SignedInfo_isUsed = 1;
    memcpy( &sig_fragment.SignedInfo, 
            &sig->SignedInfo,
            sizeof(sig_fragment.SignedInfo));
    buffer_pos = 0;
    err = encode_xmldsigExiFragment(&stream, &sig_fragment);
    if (err != 0) {
        printf("error 2: error code = %d\n", err);
        return 3;
    }

    //mbedtls_sha256(buf, (size_t)buffer_pos, digest, 0);
    PRINTF("Signature bufferpos 2: %d\r\n", buffer_pos);
    if (sig->SignatureValue.CONTENT.bytesLen > 350) {
        printf("handle_authorization: signature too long\n");
        return 4;
    }

    // Use provided context or 'Contract' context saved in charge_session struct
    if (ctx == NULL) {
        err = mbedtls_ecdsa_read_signature( &charge_session.v2g.contract_ctx,
                                            digest, 32,
                                            sig->SignatureValue.CONTENT.bytes,
                                            sig->SignatureValue.CONTENT.bytesLen);
    }
    else {
        PRINTF("USING GIVEN Context...\r\n");
        /*PRINTF("Signature BytesLen: %d\r\n", sig->SignatureValue.CONTENT.bytesLen);
        for (int i = 0; i < sig->SignatureValue.CONTENT.bytesLen; i++) {
            PRINTF("%02x ", sig->SignatureValue.CONTENT.bytes[i]);
        }
        PRINTF("\r\n");*/
        err = mbedtls_ecdsa_read_signature( ctx,
                                            digest, 32,
                                            sig->SignatureValue.CONTENT.bytes,
                                            sig->SignatureValue.CONTENT.bytesLen);
    }

    if (err != 0) {
        printf("invalid signature :%d\r\n", err);
        return 5;
    }

    return 0;
}

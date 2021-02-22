#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>

#include "v2g/v2g_security.h"

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
                            struct v2gEXIFragment *auth_fragment) {
    //struct v2gSignatureType *sig = &exiIn->V2G_Message.Header.Signature;
    unsigned char buf[256];
    uint16_t buffer_pos = 0;
    struct v2gReferenceType *req_ref = &sig->SignedInfo.Reference.array[0];
    bitstream_t stream = {
        .size = 256,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };
    //struct v2gEXIFragment auth_fragment;
    uint8_t digest[32];
    int err;
    PRINTF("Verifying V2G Signature...\r\n");
    //init_v2gEXIFragment(&auth_fragment);
    //auth_fragment.AuthorizationReq_isUsed = 1u;
    //memcpy(&auth_fragment.AuthorizationReq, req, sizeof(*req));
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
        //res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
        return 2;
    }

    /* PART 2 BELOW */
    /*
    struct xmldsigEXIFragment sig_fragment;
    init_xmldsigEXIFragment(&sig_fragment);
    sig_fragment.SignedInfo_isUsed = 1;
    memcpy(&sig_fragment.SignedInfo, &sig->SignedInfo,
            sizeof(struct v2gSignedInfoType));
    buffer_pos = 0;
    err = encode_xmldsigExiFragment(&stream, &sig_fragment);
    if (err != 0) {
        printf("error 2: error code = %d\n", err);
        return -1;
    }
    // === Hash the signature ===
    sha256(buf, buffer_pos, digest, 0);
    // === Validate the ecdsa signature using the public key ===
    if (sig->SignatureValue.CONTENT.bytesLen > 350) {
        printf("handle_authorization: signature too long\n");
        res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
        return 0;
    }
    err = ecdsa_read_signature(&sd->contract.pubkey,
                                digest, 32,
                                sig->SignatureValue.CONTENT.bytes,
                                sig->SignatureValue.CONTENT.bytesLen);
    if (err != 0) {
        res->ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
        printf("invalid signature\n");
        return 0;
    }
    sd->verified = true;
    printf("Succesful verification of signature!!!\n");
    */

    return 0;
}
#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>

#include "mbedtls/oid.h"
#include "mbedtls/md.h"
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

int verify_v2g_signature(   struct v2gEXIDocument *exiDoc,
                            mbedtls_ecdsa_context *ctx) {

    unsigned char buf[1024];
    uint16_t buffer_pos = 0;
    bitstream_t stream = {
        .size = 1024,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };
    uint8_t digest[32];
    int err;
    struct v2gEXIFragment exiFrag;
    struct v2gSignatureType *sig = &exiDoc->V2G_Message.Header.Signature;
    struct v2gReferenceType *req_ref = &sig->SignedInfo.Reference.array[0];
    struct xmldsigEXIFragment sig_fragment;

    PRINTF("Verifying V2G Signature...\r\n");

    init_v2gEXIFragment(&exiFrag);
    init_xmldsigEXIFragment(&sig_fragment);

    // Decode possible exiDoc messages' signatures
    if (exiDoc->V2G_Message.Body.CertificateInstallationReq_isUsed) {
        PRINTF("[V2G Sig] Copying CertificateInstallationReq: %d\r\n",
                sizeof(exiDoc->V2G_Message.Body.CertificateInstallationReq));
        exiFrag.CertificateInstallationReq_isUsed = 1;
        memcpy(	&exiFrag.CertificateInstallationReq,
				&exiDoc->V2G_Message.Body.CertificateInstallationReq, 
				sizeof(exiFrag.CertificateInstallationReq));

    }
    else if (exiDoc->V2G_Message.Body.AuthorizationReq_isUsed) {
        PRINTF("[V2G Sig] Copying AuthorizationReq: %d\r\n",
                sizeof(exiDoc->V2G_Message.Body.AuthorizationReq));
        exiFrag.AuthorizationReq_isUsed = 1;
        memcpy(	&exiFrag.AuthorizationReq,
				&exiDoc->V2G_Message.Body.AuthorizationReq, 
				sizeof(exiFrag.AuthorizationReq));

    }
    // Part 1 - Digest (hash)
    PRINTF("V2G SIG PART 1.1\r\n");
    if ((err = encode_v2gExiFragment(&stream, &exiFrag)) != 0) {
        PRINTF("[V2G Sig] unable to encode auth fragment\n");
        return 1;
    }
    PRINTF("V2G SIG PART 1.2: %d\r\n", buffer_pos);
    if ((err = mbedtls_sha256_ret(buf, (size_t)buffer_pos, digest, 0)) != 0) {
        PRINTF("[V2G Sig] sha256 error\r\n");
        return 2;
    }
    PRINTF("Digest len: %d\r\n", req_ref->DigestValue.bytesLen);
    if (req_ref->DigestValue.bytesLen != 32 || 
        memcmp(req_ref->DigestValue.bytes, digest, 32) != 0) {
        PRINTF("[V2G Sig] invalid digest\\rn");
        return 3;
    }

    // Part 2 - Content (xml signature + encryption)
    PRINTF("V2G SIG PART2\r\n");
    sig_fragment.SignedInfo_isUsed = 1;
    memcpy( &sig_fragment.SignedInfo, 
            &sig->SignedInfo,
            sizeof(sig_fragment.SignedInfo));
    PRINTF("V2G SIG PART 2.1\r\n");
    buffer_pos = 0;
    err = encode_xmldsigExiFragment(&stream, &sig_fragment);
    if (err != 0) {
        printf("error 2: error code = %d\n", err);
        return 4;
    }

    if ((err = mbedtls_sha256_ret(buf, (size_t)buffer_pos, digest, 0)) != 0) {
        PRINTF("[V2G Sig] sha256 error\r\n");
        return 5;
    }
    PRINTF("Signature bufferpos 2: %d\r\n", buffer_pos);
    if (sig->SignatureValue.CONTENT.bytesLen > 350) {
        printf("handle_authorization: signature too long\n");
        return 6;
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
        err = mbedtls_ecdsa_read_signature( ctx,
                                            digest, 32,
                                            sig->SignatureValue.CONTENT.bytes,
                                            sig->SignatureValue.CONTENT.bytesLen);
    }

    if (err != 0) {
        printf("invalid signature :%d\r\n", err);
        return 7;
    }

    return 0;
}

/*
sign_auth_request(req, &s->contract.key,
                        &s->contract.ctr_drbg,
                        &exiIn.V2G_Message.Header.Signature);
*/
int create_v2g_signature(struct v2gEXIFragment *exiFrag, struct v2gSignatureType *sig, mbedtls_ctr_drbg_context *ctr_drbg) {
    
    int err;
    struct xmldsigEXIFragment sig_fragment;
    memset(&sig_fragment, 0, sizeof(sig_fragment));
    struct xmldsigReferenceType *ref = &sig_fragment.SignedInfo.Reference.array[0];
    const char uri[4] = {"#ID1"};
	const char arrayCanonicalEXI[35] = {"http://www.w3.org/TR/canonical-exi/"};
	const char arrayxmldsigSHA256[51] = {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"};
	const char arrayxmlencSHA256[39] = {"http://www.w3.org/2001/04/xmlenc#sha256"};
    unsigned char buf[512];
    uint8_t digest[32];
    uint16_t buffer_pos = 0;
    bitstream_t stream = {
        .size = 512,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };

    if ((err = encode_v2gExiFragment(&stream, exiFrag)) != 0) {
        printf("error 1: error code = %d\n", err);
        return -1;
    }
    mbedtls_sha256(buf, (size_t)buffer_pos, digest, 0);

	init_xmldsigEXIFragment(&sig_fragment);
	sig_fragment.SignedInfo_isUsed = 1;
	//init_xmldsigSignedInfoType(&sig_fragment.SignedInfo);
	//init_xmldsigCanonicalizationMethodType(&sig_fragment.SignedInfo.CanonicalizationMethod);
	sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.charactersLen = 35;
	memcpy(sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.characters, arrayCanonicalEXI, 35);
	sig_fragment.SignedInfo.SignatureMethod.HMACOutputLength_isUsed = 0;
	sig_fragment.SignedInfo.SignatureMethod.Algorithm.charactersLen = 51;
	strncpy(sig_fragment.SignedInfo.SignatureMethod.Algorithm.characters, arrayxmldsigSHA256, 51);
	sig_fragment.SignedInfo.Reference.arrayLen = 1;
	ref->URI_isUsed = 1;
	ref->URI.charactersLen = 4;
	memcpy(ref->URI.characters, uri, 4);
	// "http://www.w3.org/TR/canonical-exi/"
	ref->Transforms_isUsed = 1;
	ref->Transforms.Transform.arrayLen = 1;
	ref->Transforms.Transform.array[0].Algorithm.charactersLen = 35;
	strncpy(ref->Transforms.Transform.array[0].Algorithm.characters, arrayCanonicalEXI, 35); // Will copy 35 characters from arrayCanonicalEXI to characters
	ref->Transforms.Transform.array[0].XPath.arrayLen = 0;
	ref->DigestMethod.Algorithm.charactersLen = 39;
	strncpy(ref->DigestMethod.Algorithm.characters, arrayxmlencSHA256, 39);
	ref->DigestValue.bytesLen = 32;
	memcpy(ref->DigestValue.bytes, digest, 32);
    buffer_pos = 0;

    if ((err = encode_xmldsigExiFragment(&stream, &sig_fragment)) != 0) {
        PRINTF("error 2: error code = %d\n", err);
        return 1;
    }

    memcpy(&sig->SignedInfo, &sig_fragment.SignedInfo, sizeof(struct v2gSignedInfoType));
    mbedtls_sha256(buf, buffer_pos, digest, 0);
    if ((err = mbedtls_ecdsa_write_signature(   &charge_session.v2g.contract_ctx,
                                                MBEDTLS_MD_SHA256,
                                                digest, 32,
                                                sig->SignatureValue.CONTENT.bytes,
                                                (size_t*)&sig->SignatureValue.CONTENT.bytesLen,
                                                mbedtls_ctr_drbg_random,
                                                ctr_drbg)) != 0) {
        PRINTF("ecdsa write sig err = %d\n", err);
        return 2;   
    }

    sig->KeyInfo_isUsed = 0;
	sig->Id_isUsed = 0;
	sig->Object.arrayLen = 1;
	sig->Object.array[0].Id_isUsed = 0;
	sig->Object.array[0].MimeType_isUsed = 0;
	sig->Object.array[0].Encoding_isUsed = 0;
	sig->SignatureValue.Id_isUsed = 0;

    return 0;
}

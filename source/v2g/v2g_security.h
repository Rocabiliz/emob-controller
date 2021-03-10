#ifndef V2G_SECURITY_H_
#define V2G_SECURITY_H_

#include <stdbool.h>
#include "stdint.h"

#include "mbedtls/certs.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "OpenV2G/codec/v2gEXIDatatypes.h"
#include "utilities/fsl_debug_console.h"
#include "mbedtls/ecdsa.h"

/* 
find_oid_value_in_name
https://stackoverflow.com/questions/51392127/how-can-you-extract-individual-oids-from-a-certificate-with-mbedtls

    Helper function for getting specific OIDs within a certificate
    Useful for eMAID extraction in CertificateInstallation and 
    Certificate Update
*/
size_t find_oid_value_in_name(const mbedtls_x509_name *name, const char* target_short_name, char *value, size_t value_length);
/* Taken from NIKOLA-V2G GitHub */
int verify_v2g_signature(struct v2gEXIDocument *exiDoc, mbedtls_ecdsa_context *ctx);
int create_v2g_signature(struct v2gEXIFragment *exiFrag, struct v2gSignatureType *sig, mbedtls_ctr_drbg_context *ctr_drbg);

#endif /* V2G_SECURITY_H_ */

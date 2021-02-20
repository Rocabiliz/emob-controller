#ifndef V2G_SECURITY_H_
#define V2G_SECURITY_H_

#include <stdbool.h>
#include "stdint.h"

#include "mbedtls/certs.h"
#include "mbedtls/x509_crt.h"

/* 
find_oid_value_in_name
https://stackoverflow.com/questions/51392127/how-can-you-extract-individual-oids-from-a-certificate-with-mbedtls

    Helper function for getting specific OIDs within a certificate
    Useful for eMAID extraction in CertificateInstallation and 
    Certificate Update
*/
size_t find_oid_value_in_name(const mbedtls_x509_name *name, const char* target_short_name, char *value, size_t value_length);


#endif /* V2G_SECURITY_H_ */

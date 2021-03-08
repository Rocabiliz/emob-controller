#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

// Custom includes
#include "slac/slac.h"
#include "v2g/v2g.h"
#include "charger/charger.h"
#include "v2g/v2g_comm.h"

// lwip include
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/sockets.h"

// mbed tls 
#include "ksdk_mbedtls.h"
#include "mbedtls/certs.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/ecdsa.h"

#define DEBUG_LEVEL 1

/////////////////////////
struct mbedtls_ssl_context ssl;
struct mbedtls_ssl_config conf;
struct mbedtls_pk_context secc_pkey;
struct mbedtls_entropy_context entropy;
struct mbedtls_ctr_drbg_context ctr_drbg;
struct mbedtls_x509_crt secc_crt, ca_crt;
uint8_t rx_buffer[TCP_BUFF_SIZE];
uint16_t rx_buffer_len;
/////////////////////////

// TLS Certificates
// Not CONST as they can be updated online
unsigned char CPO_Inter_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB1zCCAX2gAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJQ1BPU3Vi\n"
"Q0ExMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMTAyMTUyMDQyNTJaFw0yMjAyMTUyMDQyNTJa\n"
"MFExEjAQBgNVBAMMCUNQT1N1YkNBMjEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNWMkcwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAASQYdVyj9yY7+/yQ0Age9yiiYDCq9xnZF8k0+ScEor0jY1i\n"
"IJFJR/Yp7IPKTk0NRKZhqaFuPWSRxvOKT32M2BPMo0UwQzASBgNVHRMBAf8ECDAG\n"
"AQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUAbhG/O4OX+pKtWxWHENn\n"
"fh5VP30wCgYIKoZIzj0EAwIDSAAwRQIhALUb1TWswHBA0gsPiwd0o4+G4HGHsTOe\n"
"gu06ckUdJ4v7AiBu94OU3CzaohIsoqZtkDbytCHYzkQRdVSh3/Cxn6FQ1g==\n"
"-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIB1jCCAX2gAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJVjJHUm9v\n"
"dENBMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMTAyMTUyMDQyNTJaFw0yNTAyMTQyMDQyNTJa\n"
"MFExEjAQBgNVBAMMCUNQT1N1YkNBMTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNWMkcwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAASKFPpV8NSJWIf0Osw7EM4qyKeiPXnG5ETcKOa6MfKZN3cJ\n"
"2hOtEbwXlPPKTuHX96rOYqenQ2Ssnpb+NGmfZUO6o0UwQzASBgNVHRMBAf8ECDAG\n"
"AQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUa9qKjoWU4F4A0N/IZS9G\n"
"eJy7IBUwCgYIKoZIzj0EAwIDRwAwRAIgOx8ZSCJVCaIcN0olRFLa3wX3iO/mGThp\n"
"vMVcAaQdudkCICdijOQfLkeet1EPW1VQhVw9xwao8KEwSqjbQnrmWwTJ\n"
"-----END CERTIFICATE-----\n";
size_t CPO_Inter_Cert_len = sizeof(CPO_Inter_Cert);

unsigned char SECC_Leaf_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB0DCCAXagAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJQ1BPU3Vi\n"
"Q0EyMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMTAyMTUyMDQyNTJaFw0yMTA0MTYyMDQyNTJa\n"
"MFAxETAPBgNVBAMMCFNFQ0NDZXJ0MRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0\n"
"MQswCQYDVQQGEwJERTETMBEGCgmSJomT8ixkARkWA0NQTzBZMBMGByqGSM49AgEG\n"
"CCqGSM49AwEHA0IABGc/eXgRgEAzj6K3Kxu5uU+AKQI1qCchBYEduhfR+9ZfJ0DK\n"
"ecXKx3NKmwnir4MqGI2ol74hO346tKbZQLQSeuKjPzA9MAwGA1UdEwEB/wQCMAAw\n"
"DgYDVR0PAQH/BAQDAgOIMB0GA1UdDgQWBBQRTnfkcX8lKgL6VvDPFNmLpYUGSDAK\n"
"BggqhkjOPQQDAgNIADBFAiEA8ywemeqJW0J0Nnp0eyJBjZN3r0hxIhq72b57KPNg\n"
"CuUCICcnJtg5rorLHu7ydMTo8EfnTFo/RS8Bg9ke9tqpKoPU\n"
"-----END CERTIFICATE-----\n";
size_t SECC_Leaf_Cert_len = sizeof(SECC_Leaf_Cert);

unsigned char CA_Cert[] = "-----BEGIN CERTIFICATE-----\n" 
"MIIB0TCCAXagAwIBAgICMDkwCgYIKoZIzj0EAwIwTzERMA8GA1UEAwwITU9Sb290\n"
"Q0ExGTAXBgNVBAoMEFJJU0UgVjJHIFByb2plY3QxCzAJBgNVBAYTAkRFMRIwEAYK\n"
"CZImiZPyLGQBGRYCTU8wHhcNMjEwMjE1MjA0MjUzWhcNMzEwMjEzMjA0MjUzWjBP\n"
"MREwDwYDVQQDDAhNT1Jvb3RDQTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVjdDEL\n"
"MAkGA1UEBhMCREUxEjAQBgoJkiaJk/IsZAEZFgJNTzBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABOWU3zlG8O/DkLi9NyD8183Hrk6yUauUNZVgfY7odMBjxCqawCAu\n"
"yJ3aCXYOqkBBTmc+i4MaoqPYDl7eLNl+jwqjQjBAMA8GA1UdEwEB/wQFMAMBAf8w\n"
"DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQSqRqrto2g8Ngo3Ax5Tj+uUoCvmDAK\n"
"BggqhkjOPQQDAgNJADBGAiEA8m+9CtbmLDmHtsPyflGMhvO58kvlo+SoSHeebEC/\n"
"lHoCIQDC+sZ+Bj0Xkdk/39sabcKQqj/5DHKexQZek9IPdFSvfg==\n"
"-----END CERTIFICATE-----\n" // MO ROOT
"-----BEGIN CERTIFICATE-----\n"
"MIIB0zCCAXqgAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJVjJHUm9v\n"
"dENBMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMTAyMTUyMDQyNTFaFw0zMTAyMTMyMDQyNTFa\n"
"MFExEjAQBgNVBAMMCVYyR1Jvb3RDQTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNWMkcwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAAQcbnYsBM4dpPx1T5/+x6aWkLM1rgaVO/9WZfExnSKUjDA/\n"
"pa9yc8dAjbPDRsf/ISJ6WRK0O7oiFimW1FGVy3Sro0IwQDAPBgNVHRMBAf8EBTAD\n"
"AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU2gpIZDRKdPB/RqkJf5V+CaoH\n"
"OzIwCgYIKoZIzj0EAwIDRwAwRAIgUgnArHby6n7annG7oRdfn60ZSeNnuWqn6YZf\n"
"/O3JfJQCIEOF9tbUR7DStHGcnR1fTR2fC2gb8IkLOw/BPpn0nOfU\n"
"-----END CERTIFICATE-----\n"// V2G Root
"-----BEGIN CERTIFICATE-----\n"
"MIIB1TCCAXqgAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJT0VNUm9v\n"
"dENBMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA09FTTAeFw0yMTAyMTUyMDQyNTJaFw0zMTAyMTMyMDQyNTJa\n"
"MFExEjAQBgNVBAMMCU9FTVJvb3RDQTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNPRU0wWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAAT3WE0uhVadxzo5yIKoCu99wEYxRiBt0GBav+mGVLQnEhRY\n"
"jP910viBTHnbaWKR7bh49WWTbiZ4bfR3aaoG0q4Zo0IwQDAPBgNVHRMBAf8EBTAD\n"
"AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU/zaB4uVTRNje5q2y1bHt4jXf\n"
"W/IwCgYIKoZIzj0EAwIDSQAwRgIhAMWCJrqFeI/b0GY1VCxkxZ84vRJppJOkvB5E\n"
"MmafzbbAAiEAmhpOjjxYPE84VfokzGoKO4qrJpRPDiKm6hqj6huB9SE=\n"
"-----END CERTIFICATE-----\n"; // OEM ROOT
size_t CA_Cert_len = sizeof(CA_Cert);

unsigned char SECC_pkey[] = "-----BEGIN EC PRIVATE KEY-----\n"
"Proc-Type: 4,ENCRYPTED\n"
"DEK-Info: AES-128-CBC,0DCD40131236BE920BB75E6AA2EF3D07\n"
"\n"
"8e66qe7ikZ5oy+q4+djLdapkvjPejGbdl8lyXcurqolGe58yO38M0fvItAYhzvjf\n"
"rWTfEz93JLY0Zm6TYr4l3VlLVotUuI1P6JS1WE6hMPsrbR1Tu/8wpMhQDjX8IX7j\n"
"DwGDlb26C7QLhdZxMQwSRyQt2OQBq6YCl7eTWt8v+3I=\n"
"-----END EC PRIVATE KEY-----\n";
size_t SECC_pkey_len = sizeof(SECC_pkey);

unsigned char CPS_Leaf_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB0jCCAXegAwIBAgICMDkwCgYIKoZIzj0EAwIwUjETMBEGA1UEAwwKUHJvdlN1\n"
"YkNBMjEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVjdDELMAkGA1UEBhMCREUxEzAR\n"
"BgoJkiaJk/IsZAEZFgNDUFMwHhcNMjEwMjE1MjA0MjU0WhcNMjEwNTE2MjA0MjU0\n"
"WjBQMREwDwYDVQQDDAhDUFMgTGVhZjEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNDUFMwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAAS+jbjaGuLPc0P0ncG7yHHlkrZWSD+94mgw/2CkBzj59c7B\n"
"SbEL1O+UspEBDANNOm1VB3m/Ps5CdsOZiC6LYNbIoz8wPTAMBgNVHRMBAf8EAjAA\n"
"MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUti3euQ9dIexd+M7vTz336JJEc/kw\n"
"CgYIKoZIzj0EAwIDSQAwRgIhAPfKyBfr1pCUO3VxZjehEEETgts4aQUoa5n/ICSs\n"
"sLWwAiEA1QpTi+UGZexjme1Dh1PH4ST8O79sWRzDSQIQw+Ri0F8=\n"
"-----END CERTIFICATE-----\n"; // CPS Leaf
size_t CPS_Leaf_Cert_len = sizeof(CPS_Leaf_Cert);

unsigned char CPS_Inter_1_Cert[] = "-----BEGIN CERTIFICATE-----\n" // intermediateCPSCACerts below
"MIIB2DCCAX+gAwIBAgICMDkwCgYIKoZIzj0EAwIwUjETMBEGA1UEAwwKUHJvdlN1\n"
"YkNBMTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVjdDELMAkGA1UEBhMCREUxEzAR\n"
"BgoJkiaJk/IsZAEZFgNDUFMwHhcNMjEwMjE1MjA0MjUzWhcNMjMwMjE1MjA0MjUz\n"
"WjBSMRMwEQYDVQQDDApQcm92U3ViQ0EyMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9q\n"
"ZWN0MQswCQYDVQQGEwJERTETMBEGCgmSJomT8ixkARkWA0NQUzBZMBMGByqGSM49\n"
"AgEGCCqGSM49AwEHA0IABF/SaBVY/Mq+8KuJ1Qc6vY1e/OmsT4po4NDO32bEOrYc\n"
"/UuUh+KzpCsmO6ClJu6VJI5s/I2nyLg5k4JmzmXywYyjRTBDMBIGA1UdEwEB/wQI\n"
"MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS0GWz7jFQ+NKdjzO8E\n"
"zR4pNtb4wTAKBggqhkjOPQQDAgNHADBEAiB6LcgqAqI7QIAAO6IgUkx6RJLO14hY\n"
"171YzUwxlnKF4AIgGWjpCBXZjfDsq5YgEv7FoaLJ1j0bCwfRxDerELGNQ78=\n"
"-----END CERTIFICATE-----\n";
size_t CPS_Inter_1_Cert_len = sizeof(CPS_Inter_1_Cert);

unsigned char CPS_Inter_2_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB1zCCAX6gAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJVjJHUm9v\n"
"dENBMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMTAyMTUyMDQyNTNaFw0yNTAyMTQyMDQyNTNa\n"
"MFIxEzARBgNVBAMMClByb3ZTdWJDQTExGTAXBgNVBAoMEFJJU0UgVjJHIFByb2pl\n"
"Y3QxCzAJBgNVBAYTAkRFMRMwEQYKCZImiZPyLGQBGRYDQ1BTMFkwEwYHKoZIzj0C\n"
"AQYIKoZIzj0DAQcDQgAEF2wsHo7ndfaHln2VhnKqdXA2miJrDxPF7Fey3X+d5yLM\n"
"KEInMO1wG7pRIvCjbkkRuHzgN3oMMm8AROjG5MnygKNFMEMwEgYDVR0TAQH/BAgw\n"
"BgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFC0hJa+cD7ManzY+ngR6\n"
"6z+HwjKyMAoGCCqGSM49BAMCA0cAMEQCIBLZFI8CBOuaktiw51cT8+CEp6W6yyuF\n"
"moqLhWMWgt2wAiBXbyvV0cMu/o0km0NWGCZx4aMad2gNxRjqJWSsaMzutw==\n"
"-----END CERTIFICATE-----\n"; 
size_t CPS_Inter_2_Cert_len = sizeof(CPS_Inter_2_Cert);

unsigned char Contract_Leaf_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB1TCCAXugAwIBAgICMDkwCgYIKoZIzj0EAwIwTzERMA8GA1UEAwwITU9TdWJD\n"
"QTIxGTAXBgNVBAoMEFJJU0UgVjJHIFByb2plY3QxCzAJBgNVBAYTAkRFMRIwEAYK\n"
"CZImiZPyLGQBGRYCTU8wHhcNMjEwMjE1MjA0MjUzWhcNMjMwMjE1MjA0MjUzWjBX\n"
"MRkwFwYDVQQDDBBERS1BQkMtQzEyM0FCQzU2MRkwFwYDVQQKDBBSSVNFIFYyRyBQ\n"
"cm9qZWN0MQswCQYDVQQGEwJERTESMBAGCgmSJomT8ixkARkWAk1PMFkwEwYHKoZI\n"
"zj0CAQYIKoZIzj0DAQcDQgAEsWfvdDj3SVRQgr4W55oiJRX696ciIKHSz1eUDtus\n"
"dMPCcpxZWknPVudzTyihh4d/zjKMPMBu3Oks8vxL1sxWFqM/MD0wDAYDVR0TAQH/\n"
"BAIwADAOBgNVHQ8BAf8EBAMCA+gwHQYDVR0OBBYEFOGAeBr+Jaqn3JpTV61hCfIR\n"
"O+cGMAoGCCqGSM49BAMCA0gAMEUCIQDI4D4x6nPkRMfdBiz569OpGGIWMYRY09+P\n"
"O2x6e+GndwIgOASN1s501s9h0EYA64N/DBYiUu7ePyfj+2U04kFaxUo=\n"
"-----END CERTIFICATE-----\n"; // contractCert leaf
size_t Contract_Leaf_Cert_len = sizeof(Contract_Leaf_Cert);

unsigned char Contract_Inter_1_Cert[] = "-----BEGIN CERTIFICATE-----\n" // intermediateMOCACerts
"MIIB1DCCAXmgAwIBAgICMDkwCgYIKoZIzj0EAwIwTzERMA8GA1UEAwwITU9TdWJD\n"
"QTExGTAXBgNVBAoMEFJJU0UgVjJHIFByb2plY3QxCzAJBgNVBAYTAkRFMRIwEAYK\n"
"CZImiZPyLGQBGRYCTU8wHhcNMjEwMjE1MjA0MjUzWhcNMjUwMjE0MjA0MjUzWjBP\n"
"MREwDwYDVQQDDAhNT1N1YkNBMjEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVjdDEL\n"
"MAkGA1UEBhMCREUxEjAQBgoJkiaJk/IsZAEZFgJNTzBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABM6DYbF6V56rtJICZW14Vk0A8NpfOuEikJJrJ6ASoYDb42NJdn0c\n"
"MRwGNF5lKhtfZZk/1h1/+zLJcirh9FGpz8ujRTBDMBIGA1UdEwEB/wQIMAYBAf8C\n"
"AQAwDgYDVR0PAQH/BAQDAgHGMB0GA1UdDgQWBBSAOO5neyOcfSgrjdxomRofc6kK\n"
"ETAKBggqhkjOPQQDAgNJADBGAiEAxcVmvdfhSutENdwpkgwv8WAvlScXX1pmWS8X\n"
"sbRZoAwCIQCS8umX1PyzfbzCuvIiI/4PxtByDXnuY1LSJQV2z9Dwmw==\n"
"-----END CERTIFICATE-----\n";
size_t Contract_Inter_1_Cert_len = sizeof(Contract_Inter_1_Cert);

unsigned char Contract_Inter_2_Cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB1DCCAXmgAwIBAgICMDkwCgYIKoZIzj0EAwIwTzERMA8GA1UEAwwITU9Sb290\n"
"Q0ExGTAXBgNVBAoMEFJJU0UgVjJHIFByb2plY3QxCzAJBgNVBAYTAkRFMRIwEAYK\n"
"CZImiZPyLGQBGRYCTU8wHhcNMjEwMjE1MjA0MjUzWhcNMjUwMjE0MjA0MjUzWjBP\n"
"MREwDwYDVQQDDAhNT1N1YkNBMTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVjdDEL\n"
"MAkGA1UEBhMCREUxEjAQBgoJkiaJk/IsZAEZFgJNTzBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABME9TAGAZhz7PGrY4s8mOFZmdk7Wb/dkuh+rq6no1xZm9Q+y832U\n"
"NAuAYTGGw8SELv1yIU/Hye/riQOyrfnKCH2jRTBDMBIGA1UdEwEB/wQIMAYBAf8C\n"
"AQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR57/L4BnOwi9Y2XouUItduuYUR\n"
"vDAKBggqhkjOPQQDAgNJADBGAiEAgIUor3jx61tB7/mI6RmHEWMSdoJbF+h6OY5c\n"
"B6jX2ewCIQDQHCx9ReTzCLnl1k90MZ33yf8niZloe1mSfVW7iZZzjw==\n"
"-----END CERTIFICATE-----\n";
size_t Contract_Inter_2_Cert_len = sizeof(Contract_Inter_2_Cert);

unsigned char Contract_pkey[] = "-----BEGIN EC PRIVATE KEY-----\n"
"Proc-Type: 4,ENCRYPTED\n"
"DEK-Info: AES-128-CBC,09623169DB39B356E1CB8EC5A1B6CFAB\n"
"\n"
"9J4mfVhaLsxOkUDenmye/gQnkdMygkQxPAUdsTjjmRYufdCemBgXw4xR6Yg1g0tc\n"
"YxpYTqcwNCLbwtVt/LJKz9MMCtP/wKxbUchbhaBRdGnrvXvFOWHYhmDxEpMajmwb\n"
"h487YEZMR4Zn7ljT29qalOUtopSu9Lwx3EkPv829lug=\n"
"-----END EC PRIVATE KEY-----\n";
size_t Contract_pkey_len = sizeof(Contract_pkey);

void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	const char *p, *basename;
	(void) ctx;

	/* Extract basename from file */
	for(p = basename = file; *p != '\0'; p++) {
		if(*p == '/' || *p == '\\') {
			basename = p + 1;
		}
	}

	PRINTF("%s:%04d: |%d| %s", basename, line, level, str);
}

static int tls_net_send(void *ctx, const unsigned char *buf, size_t len) {
	err_t err;

	//PRINTF(">>> TLS SEND! Len = %d\r\n", len);
	if ((err = netconn_write(ctx, buf, len, NETCONN_COPY)) != 0) {
		PRINTF("TLS_SEND Error %d\r\n", err);
	}

    return len;
}

/* This could be optimized by doing:
- netconn_recv: reset rx_buffer
- all the shifts: buf = rx_buffer[len];
- store the last 'len' pointed by buf
*/
static int tls_net_rcv(void *ctx, unsigned char *buf, size_t len) {
    uint16_t result = 0;
    struct netbuf *temp_buf;

    //PRINTF("[TLS RX] Waiting for: %d len\r\n", len);
    // Empty rx_buffer? Receive
    if ((rx_buffer_len == 0) || (len == 0)) {

        netconn_recv(ctx, &temp_buf);
        //PRINTF("[TLS RX] receive got: %d \r\n", temp_buf->p->tot_len);

        // Copy to input buffer
        if (len == 0) {
            memcpy(buf, temp_buf->p->payload, temp_buf->p->tot_len);
            result = temp_buf->p->tot_len;
        }
        else if (temp_buf->p->tot_len > len) {
            memcpy(buf, temp_buf->p->payload, len);
            result = len;
        }
        else {
            memcpy(buf, temp_buf->p->payload, temp_buf->p->tot_len);
            result = temp_buf->p->tot_len;
        }
        if ((int)((int)temp_buf->p->tot_len - (int)len) >= 0) {
            // Update rx_buffer without the requested data (shift data by _len_)
            memcpy(rx_buffer, temp_buf->p->payload, temp_buf->p->tot_len);
            memcpy(rx_buffer, &rx_buffer[len], temp_buf->p->tot_len - len);
            rx_buffer_len = temp_buf->p->tot_len - len;
            netbuf_delete(temp_buf);  
        }
        else {
            rx_buffer_len = 0;
        }

    }
    // rx_buffer still has data from previous read call
    else {
        
        // Request of partial data from buffer
        if ((int)((int)rx_buffer_len - (int)len) >= 0) {

            // Copy to input buffer
            memcpy(buf, rx_buffer, len);

            // Update rx_buffer without the requested data (shift data by _len_)
            memcpy(rx_buffer, &rx_buffer[len], rx_buffer_len - len);
            rx_buffer_len = rx_buffer_len - len;
            
            result = len; // use the input length as result
        }
        
        // Return remaining buffer data
        else {

            // Copy to input buffer
            memcpy(buf, rx_buffer, rx_buffer_len);
            result = rx_buffer_len;

            // Clear rx_buffer
            rx_buffer_len = 0;

        }
        
    }

    return result;
}

int tls_stack_init() {
	int ret;
    uint32_t flags;
	const char *pers = "CPO";
    struct mbedtls_x509_crt v2gsig_crt;
    struct mbedtls_ecp_keypair *keypair;

	// Initialize the different descriptors
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_x509_crt_init(&secc_crt);
    mbedtls_x509_crt_init(&ca_crt);
	mbedtls_ssl_config_init(&conf);
	mbedtls_pk_init(&secc_pkey);

	// RNG
	if (( ret = mbedtls_ctr_drbg_seed(	&ctr_drbg, mbedtls_entropy_func, &entropy,
										(const unsigned char *) pers,
										strlen(pers))) != 0 ) {
		//PRINTF( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		return ret;
	}
    /* ********************
        Certificates
    **********************/
	// Client Certificate
    if ((ret = mbedtls_x509_crt_parse(&secc_crt, (const unsigned char *)SECC_Leaf_Cert, SECC_Leaf_Cert_len)) != 0) {
		PRINTF("TLS ERR 1 %d\r\n", ret);
        return ret;
	}
	if ((ret = mbedtls_x509_crt_parse(&secc_crt, (const unsigned char *)CPO_Inter_Cert, CPO_Inter_Cert_len)) != 0) {
		PRINTF("TLS ERR 1_2\r\n");
        return ret;
	}
	// CA (root) certificates
	if ((ret = mbedtls_x509_crt_parse(&ca_crt, (const unsigned char *)CA_Cert, CA_Cert_len)) != 0) {
		PRINTF("TLS ERR 1_5\r\n");
        return ret;
	}
	// Private Keys
	if ((ret = mbedtls_pk_parse_key(&secc_pkey, (const unsigned char *)SECC_pkey, SECC_pkey_len, (const unsigned char *)"123456", strlen("123456"))) != 0) {
		PRINTF("TLS ERR 2: ret = %d\r\n", ret);
        return ret;
	}

	// Config defaults
	if ((ret = mbedtls_ssl_config_defaults(	&conf,
											MBEDTLS_SSL_IS_SERVER,
											MBEDTLS_SSL_TRANSPORT_STREAM,
											MBEDTLS_SSL_PRESET_DEFAULT)) != 0 ) {
		PRINTF( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		return ret;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED); // MBEDTLS_SSL_VERIFY_NONE

	// MBEDTLS Debugging options
	mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
	mbedtls_debug_set_threshold(DEBUG_LEVEL);

	// Setup Certificate chain
    mbedtls_ssl_conf_ca_chain(&conf, &ca_crt, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &secc_crt, &secc_pkey)) != 0) {
		PRINTF( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
		return ret;
	}

    // Verify Certificate chain
    if ((ret = mbedtls_x509_crt_verify(&secc_crt, &ca_crt, NULL, NULL, &flags, NULL, NULL)) != 0) {
        PRINTF( "TLS Verify certs failed: %d\r\n", ret);
		return ret;
    }

    // Initialize contract structure for XML signature validation
	mbedtls_x509_crt_init(&v2gsig_crt);
    mbedtls_ecdsa_init(&charge_session.v2g.contract_ctx);
    if ((ret = mbedtls_x509_crt_parse(	&v2gsig_crt, 
                                        (const unsigned char *)Contract_Leaf_Cert, 
                                        Contract_Leaf_Cert_len)) != 0) {
		PRINTF("TLS INIT: CONTRACT CERT LOAD ERR : %d\r\n", ret);
	}
    keypair = mbedtls_pk_ec(v2gsig_crt.pk);
    if ((ret = mbedtls_ecdsa_from_keypair(&charge_session.v2g.contract_ctx, keypair)) != 0) {
        PRINTF("TLS INIT: loading ecdsa from keypair err: %d\r\n", ret);
    }
    mbedtls_x509_crt_free(&v2gsig_crt); // is this ok?
    
    PRINTF("[TLS] Init successful!\r\n");
	return ret;
}

int tls_conn_init(struct netconn *conn) {
    int ret = ERR_OK;
    mbedtls_ssl_init(&ssl);

    // RX buffer init
    memset(rx_buffer, 0, sizeof(rx_buffer));
    rx_buffer_len = 0;

    // Post-init operations
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		PRINTF( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
		ret = ret;
	}

    mbedtls_ssl_set_bio(&ssl, conn, &tls_net_send, &tls_net_rcv, NULL);
    return ret;
}

void tls_close_conn() {
    // RX buffer init
    memset(rx_buffer, 0, sizeof(rx_buffer));
    rx_buffer_len = 0;

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
}

int tls_handshake() {
    return mbedtls_ssl_handshake(&ssl);
}

err_t v2g_recv(struct netconn *conn, uint8_t *buf, uint16_t *len) {
    err_t err = ERR_OK;
    struct netbuf *netbuf;
    int tls_ret = 0;

    // TLS Enabled
    if (charge_session.v2g.tls) {
        tls_ret = mbedtls_ssl_read(&ssl, buf, TCP_BUFF_SIZE);
        if (tls_ret > 0) {
            *len = (uint16_t)tls_ret;
            err = ERR_OK;
        }
        else {
            *len = 0;
            err = 1;
        }

    }
    // TCP only
    else {
        if ((err = netconn_recv(conn, &netbuf)) != ERR_OK) {
            PRINTF("V2G RX netconn_Recv err: %d\r\n", err);
            return err;
        }
        memcpy(buf, netbuf->p->payload, netbuf->p->len);
        *len = netbuf->p->len;
        netbuf_delete(netbuf);
    }

    return err;
}

err_t v2g_send(struct netconn *conn, uint8_t *buf, size_t len) {
    err_t res;

    // TLS Enabled
    if (charge_session.v2g.tls) {
        res = (err_t) (mbedtls_ssl_write(&ssl, buf, len) == 0) ? 1 : 0;
    }
    // TCP only
    else {
	    res = netconn_write(conn, buf, len, NETCONN_COPY);
    }

    return res;
}

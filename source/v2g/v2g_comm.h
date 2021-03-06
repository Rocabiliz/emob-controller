#ifndef V2G_COMM_H_
#define V2G_COMM_H_

#include "stdint.h"
#include "v2g/v2g.h"
#include "lwip/netif.h"
#include "lwip/netbuf.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "lwip/api.h"

// TLS Certificates
/*extern const unsigned char mbedtls_intermediate_cpo_crt[];
extern const unsigned char mbedtls_secc_crt[];
extern const unsigned char SAProvisioningCertificateChain_leaf[];
extern const unsigned char SAProvisioningCertificateChain_inter_1[];
extern const unsigned char SAProvisioningCertificateChain_inter_2[];
extern const unsigned char ContractSignatureCertChain_leaf[];
extern const unsigned char ContractSignatureCertChain_inter_1[];
extern const unsigned char ContractSignatureCertChain_inter_2[];
extern const unsigned char ContractPrivKey[];
extern const unsigned char mbedtls_srv_privkey[];
extern const unsigned char CACertificatesList[]; // investigate: https://github.com/ARMmbed/mbedtls/pull/2532
*/
void my_debug(void *ctx, int level, const char *file, int line, const char *str);
int tls_stack_init();
int tls_conn_init(struct netconn *conn);
void tls_close_conn();
int tls_handshake();
err_t v2g_recv(struct netconn *conn, uint8_t *buf, uint16_t *len);
err_t v2g_send(struct netconn *conn, uint8_t *buf, size_t len);

#endif

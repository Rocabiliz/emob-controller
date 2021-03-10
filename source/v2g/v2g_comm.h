#ifndef V2G_COMM_H_
#define V2G_COMM_H_

#include "stdint.h"
#include "v2g/v2g.h"
#include "lwip/netif.h"
#include "lwip/netbuf.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "lwip/api.h"

#define TLS_TIMEOUT_MS 10000

// TLS Certificates
extern unsigned char CPO_Inter_Cert[];
extern size_t CPO_Inter_Cert_len;
extern unsigned char SECC_Leaf_Cert[];
extern size_t SECC_Leaf_Cert_len;
extern unsigned char CA_Cert[];
extern size_t CA_Cert_len;
extern unsigned char SECC_pkey[];
extern size_t SECC_pkey_len;
extern unsigned char CPS_Leaf_Cert[];
extern size_t CPS_Leaf_Cert_len;
extern unsigned char CPS_Inter_1_Cert[];
extern size_t CPS_Inter_1_Cert_len;
extern unsigned char CPS_Inter_2_Cert[];
extern size_t CPS_Inter_2_Cert_len;
extern unsigned char Contract_Leaf_Cert[];
extern size_t Contract_Leaf_Cert_len;
extern unsigned char Contract_Inter_1_Cert[];
extern size_t Contract_Inter_1_Cert_len;
extern unsigned char Contract_Inter_2_Cert[];
extern size_t Contract_Inter_2_Cert_len;
extern unsigned char Contract_pkey[];
extern size_t Contract_pkey_len;

void my_debug(void *ctx, int level, const char *file, int line, const char *str);
int tls_stack_init();
int tls_conn_init(struct netconn *conn);
void tls_close_conn();
int tls_handshake();
err_t v2g_recv(struct netconn *conn, uint8_t *buf, uint16_t *len);
err_t v2g_send(struct netconn *conn, uint8_t *buf, size_t len);

#endif

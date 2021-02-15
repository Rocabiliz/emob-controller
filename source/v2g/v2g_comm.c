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

#define DEBUG_LEVEL 1

/////////////////////////
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert, verify_cert;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_pk_context pkey;
uint8_t rx_buffer[TCP_BUFF_SIZE];
uint16_t rx_buffer_len;
/////////////////////////

//  TLS Certificates
const char mbedtls_intermediate_cpo_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB1jCCAX2gAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJQ1BPU3Vi\n"
"Q0ExMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMDEyMTQxODMzNTFaFw0yMTEyMTQxODMzNTFa\n"
"MFExEjAQBgNVBAMMCUNQT1N1YkNBMjEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNWMkcwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAARvGViyGHVLNb6C+JxwMmri2Van+57NxU3PMTRd5FgcaRjD\n"
"ujeu73JBhxibKwKPqOPnkTGwc070I9+rMp+8/OAeo0UwQzASBgNVHRMBAf8ECDAG\n"
"AQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUQ9iJVvDdgvVKhwQe6G/4\n"
"uIJSd3owCgYIKoZIzj0EAwIDRwAwRAIgeT15liBZws3floP8XNtLvB2iJ0+atx44\n"
"DkYiy9FrES4CIDJm3B/VDrXflBgWU4+Fska6bkES9DJjbzEoya8QPvUF\n"
"-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIB1zCCAX2gAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJVjJHUm9v\n"
"dENBMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMDEyMTQxODMzNTFaFw0yNDEyMTMxODMzNTFa\n"
"MFExEjAQBgNVBAMMCUNQT1N1YkNBMTEZMBcGA1UECgwQUklTRSBWMkcgUHJvamVj\n"
"dDELMAkGA1UEBhMCREUxEzARBgoJkiaJk/IsZAEZFgNWMkcwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAATxHIFrKmIgJ3pdpmueliVdOY3cARI5KSVqFnj5zgCxzYEf\n"
"75dcH0/NO5oZ1TWiso5R54lwhBS/17i9DghHJh6go0UwQzASBgNVHRMBAf8ECDAG\n"
"AQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUbxSHVY1tTjjnlUjG7Wi3\n"
"XqAsOqEwCgYIKoZIzj0EAwIDSAAwRQIgdOHQEpy3ni4rOzz+2vNhr6BwydYLIWS+\n"
"CB81DpEWXzUCIQC9OrExcGCtQEXNWOuS6WA9AdIcMvtAJt6OEJ7ot4ziWw==\n"
"-----END CERTIFICATE-----\n";

const char mbedtls_secc_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIB0TCCAXagAwIBAgICMDkwCgYIKoZIzj0EAwIwUTESMBAGA1UEAwwJQ1BPU3Vi\n"
"Q0EyMRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0MQswCQYDVQQGEwJERTETMBEG\n"
"CgmSJomT8ixkARkWA1YyRzAeFw0yMDEyMTQxODMzNTJaFw0yMTAyMTIxODMzNTJa\n"
"MFAxETAPBgNVBAMMCFNFQ0NDZXJ0MRkwFwYDVQQKDBBSSVNFIFYyRyBQcm9qZWN0\n"
"MQswCQYDVQQGEwJERTETMBEGCgmSJomT8ixkARkWA0NQTzBZMBMGByqGSM49AgEG\n"
"CCqGSM49AwEHA0IABME3a0IJxgNt3gpsJdKer6r0WrfMVnI0xH/sgdpQGIfbit2P\n"
"t4uVYRRm91ZDz4tHLtRTn7xHvsAWgLRSl0al7BijPzA9MAwGA1UdEwEB/wQCMAAw\n"
"DgYDVR0PAQH/BAQDAgOIMB0GA1UdDgQWBBTnpjh1TRUBfvuVKn5gMXxq9DyuBTAK\n"
"BggqhkjOPQQDAgNJADBGAiEAjzuZYLBZ8pq3Y1vGdRrPQHCxlcybW9Xg44NDYPe4\n"
"QH8CIQD4UPtL9NW+knGS0JU27hPIGNCSrDsY7F+mDxUHMcerpg==\n"
"-----END CERTIFICATE-----\n";

const char mbedtls_srv_privkey[] = "-----BEGIN EC PRIVATE KEY-----\n"
"Proc-Type: 4,ENCRYPTED\n"
"DEK-Info: AES-128-CBC,CD80827B05DC10307B3A6DA71FC5E1F6\n"
"\n"
"yU71hT5qBF0olK96U7L9hWHMgoccGfp08cQe2tlNCjyQhWaXnrmgGsgZn2ncrocv\n"
"tpcNtfh7Oj/zHD/u749l4KocQLjVBkd90e1ni9d2xW1EFRDqUWRiSWj8cbSowMpK\n"
"alSX8Dop4duSH3uqiDZQCP3y5PY9FCUURBPiHEHQk2A=\n"
"-----END EC PRIVATE KEY-----\n";

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

static uint16_t tls_net_send(void *ctx, const unsigned char *buf, size_t len) {
	err_t err;
    uint8_t buffer[TCP_BUFF_SIZE];
    
	//PRINTF(">>> TLS SEND! Len = %d\r\n", len);
    
	err = netconn_write(ctx, buf, len, NETCONN_COPY);

    return len;
}

/* This could be optimized by doing:
- netconn_recv: reset rx_buffer
- all the shifts: buf = rx_buffer[len];
- store the last 'len' pointed by buf
*/
static uint16_t tls_net_rcv(void *ctx, unsigned char *buf, size_t len) {
    uint16_t result = 0;
    struct netbuf *temp_buf;
    int i = 0;

    //PRINTF("### TLS RECEIVE! Waiting for: %d len\\r\n", len);
    
    // Empty rx_buffer? Receive
    if ((rx_buffer_len == 0) || (len == 0)) {

        netconn_recv(ctx, &temp_buf);
        //PRINTF("TLS receive got: %d \r\n", temp_buf->p->tot_len);

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


        // Update rx_buffer without the requested data (shift data by _len_)
        memcpy(rx_buffer, temp_buf->p->payload, temp_buf->p->tot_len);
        memcpy(rx_buffer, &rx_buffer[len], temp_buf->p->tot_len - len);
        rx_buffer_len = temp_buf->p->tot_len - len;
        netbuf_delete(temp_buf);  

    }

    // rx_buffer still has data from previous read call
    else {
        
        // Request of partial data from buffer
        if (rx_buffer_len > len) {

            // Copy to input buffer
            memcpy(buf, rx_buffer, len);

            // Update rx_buffer without the requested data (shift data by _len_)
            memcpy(rx_buffer, &rx_buffer[len], rx_buffer_len - len);
            rx_buffer_len = rx_buffer_len - len;

        }
        
        // Return remaining buffer data
        else {

            // Copy to input buffer
            memcpy(buf, rx_buffer, rx_buffer_len);
            result = rx_buffer_len;

            // Clear rx_buffer
            rx_buffer_len = 0;
        }
        
        result = len; // use the input length as result
    }

    return result;
}

int tls_stack_init() {
	int ret;
	const char *pers = "CPO";
	const char *pass = "123456";

	//PRINTF("TLS INIT!\r\n");

	// Initialize the different descriptors
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ssl_config_init(&conf);
	mbedtls_pk_init(&pkey);

	// RNG
	if (( ret = mbedtls_ctr_drbg_seed(	&ctr_drbg, mbedtls_entropy_func, &entropy,
										(const unsigned char *) pers,
										strlen(pers))) != 0 ) {
		//PRINTF( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		return ret;
	}
	// Certificates
	if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_secc_crt, sizeof(mbedtls_secc_crt))) != 0) {
		//PRINTF("TLS ERR 1\r\n");
        return ret;
	}
	if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_intermediate_cpo_crt, sizeof(mbedtls_intermediate_cpo_crt))) != 0) {
		//PRINTF("TLS ERR 1_2\r\n");
        return ret;
	}

	// Private Key
	if ((ret = mbedtls_pk_parse_key(&pkey, mbedtls_srv_privkey, sizeof(mbedtls_srv_privkey), "123456", strlen("123456"))) != 0) {
		//PRINTF("TLS ERR 2: ret = %d\r\n", ret);
        return ret;
	}

	// Config defaults
	if ((ret = mbedtls_ssl_config_defaults(	&conf,
											MBEDTLS_SSL_IS_SERVER,
											MBEDTLS_SSL_TRANSPORT_STREAM,
											MBEDTLS_SSL_PRESET_DEFAULT)) != 0 ){
		//PRINTF( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
		return ret;
	}

	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); /* \todo change verification mode! */

	// MBEDTLS Debugging options
	mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
	mbedtls_debug_set_threshold(DEBUG_LEVEL);

	// Certificate chain
	// Verify certificates
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &cacert, &pkey)) != 0) {
		//PRINTF( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
		return ret;
	}

	return ret;
}

int tls_conn_init(int *conn) {
    int ret = ERR_OK;
    mbedtls_ssl_init(&ssl);

    // RX buffer initi
    memset(rx_buffer, 0, sizeof(rx_buffer));
    rx_buffer_len = 0;

    // Post-init operations
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		PRINTF( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
		ret = ret;
	}
	if ((ret = mbedtls_ssl_set_hostname(&ssl, "CPO")) != 0){
		PRINTF( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
		ret = ret;
	}

    mbedtls_ssl_set_bio(&ssl, conn, tls_net_send, tls_net_rcv, NULL);
    return ret;
}

void tls_close_conn() {
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
}

int tls_handshake() {
    return mbedtls_ssl_handshake(&ssl);
}

err_t v2g_recv(struct netconn *conn, uint8_t buf[TCP_BUFF_SIZE], uint16_t *len) {
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

err_t v2g_send(struct netconn *conn, uint8_t buf[TCP_BUFF_SIZE], size_t len) {
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

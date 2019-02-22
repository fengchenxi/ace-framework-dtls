#include "contiki.h"
#include "cbor-encoder.h"
#include "cbor-web-token.h"



uint16_t generate_cose_key( uint8_t *payload_bytes,
	                       char *cose_key_type,
	                       char *cose_key_id,
	                       char *key);

//uint16_t generate_ipsec(uint8_t *payload_bytes,
//                       char *mode,
//                       uint32_t life,
//                       char *ip_c,
//                       char *ip_rs,
//                       uint32_t spi_sa_c,
//                       uint32_t spi_sa_rs,
//                       uint32_t prot_type,
//                       uint32_t enc_alg,
//                       const char *seed);
uint16_t generate_cnf(cbor_data *payload, 
                        uint32_t cose_len,
                        char *cose_key,
                        char *cose_encrypted,
                        char *cnf_key_id);
#if WITH_DTLS
#if DTLS_PSK
uint16_t generate_access_token_for_psk( cbor_data *payload,
  // uint8_t *payload_bytes,
                               char *subject,
                               char *audience,
                               uint32_t exp_time,
                               char *client_id,
                               char *scope,
                               uint32_t grant_type,
                               char *access_token,
                               char *token_type,
                               char *username,
                               char *password,
                               char *profile);
#endif
#endif

/*uint16_t generate_access_token_for_rpk( cbor_data *payload,
                               char *subject,
                               char *audience,
                               uint32_t exp_time,
                               char *client_id,
                               char *scope,
                               uint32_t grant_type,
                               char *access_token,
                               char *token_type,
                               char *username,
                               char *password,
                               char *profile);
*/
uint16_t generate_access_token_no_dtls( cbor_data *payload,
	                           char *subject,
	                           char *audience,
	                           uint32_t exp_time,
	                           char *client_id,
	                           char *scope,
	                           uint32_t grant_type,
	                           char *access_token,
	                           char *token_type,
	                           char *username,
	                           char *password,
	                           char *profile);

uint16_t generate_dummy_access_token(cbor_data *payload, uint8_t mode);



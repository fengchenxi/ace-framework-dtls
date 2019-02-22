#include "cbor-encoder.h"
#include "cbor-web-token.h"
#include "cose-encoder.h"


#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

#include "contiki.h"



uint16_t generate_cose_key( uint8_t *payload_bytes,
	                       char *cose_key_type,
	                       char *cose_key_id,
	                       char *key) {

	 cbor_data payload;
	 payload.buf = payload_bytes;
	 payload.ptr = 0;
	 /* encode CBOR web token as a payload */
	 encode_map_array(&payload, 3);

	 encode_cose_key(&payload, COSE_KEY_TYPE, cose_key_type);
	 encode_cose_key(&payload, COSE_KEY_ID, cose_key_id);
	 encode_cose_key(&payload, PSK_KEY, key);

	 return payload.ptr;
}

/*uint16_t generate_ipsec(uint8_t *payload_bytes,
                       char *mode,
                       uint32_t life,
                       char *ip_c,
                       char *ip_rs,
                       uint32_t spi_sa_c,
                       uint32_t spi_sa_rs,
                       uint32_t prot_type,
                       uint32_t enc_alg,
                       const char *seed) {

	 cbor_data payload;
	 payload.buf = payload_bytes;
	 payload.ptr = 0;
	 uint8_t dstr[4];
	 // encode CBOR web token as a payload 
	 encode_map_array(&payload, 9);

	 encode_ipsec(&payload, MODE, (uint8_t *) mode);
	 integer2bytestring(life, 4, dstr);
	 encode_ipsec(&payload, LIFE, dstr);
	 encode_ipsec(&payload, IP_C, (uint8_t *) ip_c);
	 encode_ipsec(&payload, IP_RS, (uint8_t *)ip_rs);
	 integer2bytestring(spi_sa_c, 4, dstr);
	 encode_ipsec(&payload, SPI_SA_C, dstr);
	 integer2bytestring(spi_sa_rs, 4, dstr);
	 encode_ipsec(&payload, SPI_SA_RS, dstr);
	 integer2bytestring(prot_type, 4, dstr);
	 encode_ipsec(&payload, IPSEC_PROT_TYPE, dstr);
	 integer2bytestring(enc_alg, 4, dstr);
	 encode_ipsec(&payload, IPSEC_ENC_ALG, dstr);
	 encode_ipsec(&payload, SEED, (uint8_t *) seed);
	 return payload.ptr;
}*/

uint16_t generate_cnf( uint8_t *payload_bytes,
						   uint32_t cose_len,
	                       char *cose_key,
	                       char *cose_encrypted,
	                       char *cnf_key_id){
	                       //uint32_t ipsec_len,
	                       //char *ipsec
	                       //char *kmp) {

	cbor_data payload;
	payload.buf = payload_bytes;
	payload.ptr = 0;
	/* encode CBOR web token as a payload */
	uint8_t num_params = 3;
	if(cose_key == NULL){
		num_params --;
	}
//	if(ipsec == NULL){
//		num_params --;
//	}
	// printf('\n%d\n',num_params);
	encode_map_array(&payload, num_params);

	encode_cnf(&payload, COSE_ENCRYPTED, (uint8_t *) cose_encrypted);
	encode_cnf(&payload, CNF_KEY_ID, (uint8_t *) cnf_key_id);
	//encode_cnf(&payload, KMP, (uint8_t *) kmp);
	if(cose_key != NULL){
		encode_struc_in_cnf(&payload, COSE_KEY, (uint8_t *) cose_key, cose_len);
	}
//	if(ipsec != NULL){
//		encode_struc_in_cnf(&payload, IPSEC_STRUC, (uint8_t *) ipsec, ipsec_len);
//	}
	return payload.ptr;
}

// }
uint16_t generate_access_token(cbor_data *payload,
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
	                           char *profile) {

	 // cbor_data payload;
	 // payload.buf = payload_bytes;
	 // payload.ptr = 0;
	 uint8_t dstr[4];

	 /* encode CBOR web token as a payload */
	 //print_cbor(payload);
	 encode_map_array(payload, 18);
	 encode_cwt_directly(payload, SUB, (uint8_t *) subject);
	 encode_cwt_directly(payload, AUD, (uint8_t *) audience);
	 integer2bytestring(exp_time, 4, dstr);
	 encode_cwt_directly(payload, EXP, dstr);
	 encode_cwt_directly(payload, CLIENT_ID, (uint8_t *) client_id);
	 encode_cwt_directly(payload, SCOPE, (uint8_t *) scope);
	 integer2bytestring(grant_type, 4, dstr);
	 encode_cwt_directly(payload, GRANT_TYPE, dstr); // password
	 encode_cwt_directly(payload, ACCESS_TOKEN, (uint8_t *) access_token);
	 encode_cwt_directly(payload, TOKEN_TYPE, (uint8_t *) token_type);
	 encode_cwt_directly(payload, USERNAME, (uint8_t *) username);
	 encode_cwt_directly(payload, PASSWORD, (uint8_t *) password);
	 encode_cwt_directly(payload, PROFILE, (uint8_t *) profile);
	encode_cwt_directly(payload, CNF, (uint8_t *)"");

	encode_cnf(payload, COSE_ENCRYPTED,(uint8_t *)"cose_encrypted");
	encode_cnf(payload, CNF_KEY_ID, (uint8_t *)"cnf_key_id");
//	encode_cnf(payload, KMP, "ikev2");

	 encode_cnf(payload, COSE_KEY,(uint8_t *)"");
	 encode_cose_key(payload, COSE_KEY_TYPE, "Symmetric");
	 encode_cose_key(payload, COSE_KEY_ID, "919191");
	 encode_cose_key(payload, PSK_KEY, "wangpangpang");
//	 encode_cnf(payload, IPSEC_STRUC,"");
//	 encode_ipsec(payload, MODE, (uint8_t *) "transport");
//	 integer2bytestring(1235, 4, dstr);
//	 encode_ipsec(payload, LIFE, dstr);
//	 encode_ipsec(payload, IP_C, "");
//	 encode_ipsec(payload, IP_RS, "");
//	 integer2bytestring(1, 4, dstr);
//	 encode_ipsec(payload, SPI_SA_C, dstr);
//	 integer2bytestring(2, 4, dstr);
//	 encode_ipsec(payload, SPI_SA_RS, dstr);
//	 integer2bytestring(0, 4, dstr);
//	 encode_ipsec(payload, IPSEC_PROT_TYPE, dstr);
//	 integer2bytestring(0, 4, dstr);
//	 encode_ipsec(payload, IPSEC_ENC_ALG, dstr);
//	 encode_ipsec(payload, SEED,  "aa280649d44");
	 printf("token %ld \n", payload->ptr);
	 return payload->ptr;
}

uint16_t generate_oauth_as_cwt_payload(cbor_data *payload_bytes) {
 	uint32_t time = 3600;
 	uint32_t grant_type = 10;

	return generate_access_token(payload_bytes,
								 "subject1",
								 "coap://example.com",
								 time,
								 "a_client_id",
								 "read_scope",
								 grant_type,
								 "an_encoded_access_token",
								 "P-o-P",
								 "client_username",
								 "client_password",
								 "coap_ipsec");
	// cbor_data payload;
	// payload.buf = payload_bytes;
	// payload.ptr = 0;

	// /* encode CBOR web token as a payload */
	// encode_map_array(&payload, 11);

	// encode_cwt_directly(&payload, SUB, (uint8_t *) "subject");
	// encode_cwt_directly(&payload, AUD, (uint8_t *) "coap://example.com");
	// uint8_t dstr[4];
	// uint32_t time;
	// time = 1479132451;
	// integer2bytestring(time, 4, dstr);

	// encode_cwt_directly(&payload, EXP, dstr);
	// encode_cwt_directly(&payload, CLIENT_ID, (uint8_t *) "a_client_id");
	// encode_cwt_directly(&payload, SCOPE, (uint8_t *) "read");
	// encode_cwt_directly(&payload, GRANT_TYPE, 0); // password
	// encode_cwt_directly(&payload, ACCESS_TOKEN, (uint8_t *) "an_encoded_access_token");
	// encode_cwt_directly(&payload, TOKEN_TYPE, (uint8_t *) "P-o-P");
	// encode_cwt_directly(&payload, USERNAME, (uint8_t *) "client_username");
	// encode_cwt_directly(&payload, PASSWORD, (uint8_t *) "client_password");
	// // encode_cwt_directly(&payload, CNF, (uint8_t *) "coap://example.com");
	// encode_cwt_directly(&payload, PROFILE, (uint8_t *) "coap_ipsec");

	// return payload.ptr;
}





PROCESS(cbor_test, "cbor test");
AUTOSTART_PROCESSES(&cbor_test);
PROCESS_THREAD(cbor_test, ev, data)
{
	PROCESS_BEGIN();

	/************** at the OAuth Server *****************/
	uint8_t payload_bytes[1200];
	uint16_t payload_len;

  	cbor_data cb_data1;
  	cb_data1.buf =  payload_bytes;
  	cb_data1.ptr = 0;
	 static uint8_t claim[950];
//  	ipsec_sa new_ipsec_sa;
	payload_len = generate_oauth_as_cwt_payload(&cb_data1);

	// enum cose_type ctype = COSE_SIGN1;
	enum cose_type ctype = COSE_ENCRYPT0;
	// //enum cose_type ctype = COSE_MAC0;


	uint8_t data_bytes[2000];
	cbor_data cb_data;
	cb_data.buf = data_bytes;
	cb_data.ptr = 0;
	wrapin_cose_envelope(&cb_data, ctype, payload_bytes, payload_len);

	printf("payload len %ld\n", cb_data1.ptr);

	/*********** IoT Server received from client *****************/
	uint8_t payload_bytes1[2000];
	cb_data.buf = data_bytes;
	cb_data.ptr = 0;
	payload_len = unwrap_cose_envelope(&cb_data, ctype, payload_bytes1, payload_len);
	printf("payload len %d\n", payload_len);
	if(payload_len) {
		cb_data.buf = payload_bytes;
		cb_data.ptr = 0;
		dtls_channel new_dtls_channel;
	//	ipsec_sa newipsec;
		decode_cbor_web_token(&cb_data, claim, &new_dtls_channel);
		// decode_ipsec(&data);
		// decode_cnf(&data);
	}
	PROCESS_END();
}


/** @} */
/** @} */
/** @} */

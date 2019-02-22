
// #include "cbor-encoder.h"
// #include "cbor-web-token.h"
// #include "cose-encoder.h"

#include "contiki.h"
#include "cbor-encoder.h"
#include "cbor-web-token.h"

#include "sys/log.h"
#define LOG_MODULE "Test"
#define LOG_LEVEL LOG_LEVEL_INFO

void hex_string_to_array(const char *hexstring,  uint8_t *val){
//	const char * my_str = hexstring;
	//char * my_copy;
	// my_copy = malloc(sizeof(char) * strlen(my_str));
	// strcpy(my_copy,my_str);
    int i;
    uint16_t str_len = strlen(hexstring);
	LOG_INFO("cert len * 2: %d\n",strlen(hexstring));
    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02hhx", &val[i]);
        // printf("\tbytearray %d: %02x\n", i, val[i]);
    }
}

uint16_t generate_cnf(cbor_data *payload,
	// uint8_t *payload_bytes,
			       uint32_t cose_len,
	                       char *cose_key,
	                       char *cose_encrypted,
	                       char *cnf_key_id) {

	// cbor_data payload;
	// payload.buf = payload_bytes;
	// payload.ptr = 0;
	/* encode CBOR web token as a payload */
	uint8_t num_params = 3;
	if(cose_key == NULL){
		num_params --;
	}
	encode_map_array(payload, num_params);

	encode_cnf(payload, COSE_ENCRYPTED, (uint8_t *) cose_encrypted);
	encode_cnf(payload, CNF_KEY_ID, (uint8_t *) cnf_key_id);
	if(cose_key != NULL){
		encode_struc_in_cnf(payload, COSE_KEY, (uint8_t *) cose_key, cose_len);
	}
	return payload->ptr;
}


uint16_t generate_access_token_no_dtls(cbor_data *payload,
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

	 uint8_t dstr[4];

// encode_cwt_directly(cbor_data *data, uint8_t claim_key, uint8_t *claim) 
//void encode_map_array(cbor_data *data, uint32_t len);
//integer2bytestring(uint32_t data, uint8_t num_bytes, uint8_t *dstr)
//claim key The CBOR map key used to identify a claim
	encode_map_array(payload, 12);

	encode_cwt_directly(payload, SUB, (uint8_t *) subject);
 
	encode_cwt_directly(payload, AUD, (uint8_t *) audience);
        
	integer2bytestring(exp_time, 4, dstr);
	encode_cwt_directly(payload, EXP, dstr);

	encode_cwt_directly(payload, CLIENT_ID, (uint8_t *) client_id);

	encode_cwt_directly(payload, SCOPE, (uint8_t *) scope);

	integer2bytestring(grant_type, 4, dstr);
	encode_cwt_directly(payload, GRANT_TYPE, dstr);

	encode_cwt_directly(payload, ACCESS_TOKEN, (uint8_t *) access_token);
	encode_cwt_directly(payload, TOKEN_TYPE, (uint8_t *) token_type);
	encode_cwt_directly(payload, USERNAME, (uint8_t *) username);
	encode_cwt_directly(payload, PASSWORD, (uint8_t *) password);
	encode_cwt_directly(payload, PROFILE, (uint8_t *) profile);
	encode_cwt_directly(payload, CNF, (uint8_t *) "");

	// encode_cnf(payload, COSE_ENCRYPTED,"");
	// encode_cnf(payload, CNF_KEY_ID, "");
	// encode_cnf(payload, KMP, "");

	// // encode_cnf(payload, COSE_KEY,"");
	// encode_cose_key(payload, COSE_KEY_TYPE, "");
	// encode_cose_key(payload, COSE_KEY_ID, "1234");
	// encode_cose_key(payload, KEY, "3bda5b6c05595de5642bf613f8d1afd4d4a80759");
	LOG_INFO_("token %lu \n", payload->ptr);
	return payload->ptr;
}

#if WITH_DTLS

uint16_t generate_access_token_for_psk( cbor_data *payload,
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

	 uint8_t dstr[4];

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


	encode_cnf(payload, COSE_ENCRYPTED,(uint8_t *)"");
	encode_cnf(payload, CNF_KEY_ID, (uint8_t *)"");




	//encode_cnf(payload, KMP, "ikev2");

	encode_cnf(payload, COSE_KEY,(uint8_t *)"");
	encode_cose_key(payload, COSE_KEY_ID, "Client_identity");
	encode_cose_key(payload, COSE_KEY_TYPE,"Symmetric");
	encode_cose_key(payload, PSK_KEY, "secretPSK");

//	encode_cose_key(payload, ALG,"HS256");	

//	LOG_INFO_("token %lu \n", payload->ptr);

//	printf("token %ld \n", payload->ptr);
	return payload->ptr;
}

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
	                           char *profile) {

	 uint8_t dstr[4];
//void integer2bytestring(uint32_t data, uint8_t num_bytes, uint8_t *dstr)
	encode_map_array(payload, 20);
        encode_cwt_directly(payload, SUB, (uint8_t *) subject);
        //integer2bytestring(sub, 2, dstr);
        //encode_cwt_directly(payload, SUB, dstr);
	encode_cwt_directly(payload, AUD, (uint8_t *) audience);
        //integer2bytestring(aud, 3, dstr);
        //encode_cwt_directly(payload, AUD, dstr);

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
	encode_cwt_directly(payload, CNF, "");

	encode_cnf(payload, COSE_ENCRYPTED,"");
	encode_cnf(payload, CNF_KEY_ID, "");
	//encode_cnf(payload, KMP, "ikev2");

	encode_cnf(payload, COSE_KEY,"");
	encode_cose_key(payload, COSE_KEY_TYPE, "EC2");
	encode_cose_key(payload, COSE_KEY_ID, "1234");
        encode_cose_key(payload,COSE_KEY_CRV,"P-256");
	encode_cose_key(payload,COSE_KEY_X, "RS_public_key_x");
        encode_cose_key(payload,COSE_KEY_Y,"RS_public_key_y");
	//encode_cose_key(payload, KEY, "308201443081EBA00302010202086F51FF8D8C545AE9300A06082A8648CE3D0403023017311530130603550403130C534943532054455354204341301E170D3135303631353037353332335A170D3138303631343037353332335A3015311330110603550403130A554450205365727665723059301306072A8648CE3D020106082A8648CE3D030107034200043E4A25E3BFF3463B0E3A06DBF42DE2AE694EA58422F815F558A55979DC6DC65BCC1298C8BDD949346A1B4CCEE86340376B7A007C2CB5D76B29081B7608664751A3233021301F0603551D230418301680144C3C3859EA14F1D9FB9D1A2B25DD436030E25488300A06082A8648CE3D0403020348003045022062589EB3D264EA6E3803C86D07A56D27E8FAB4EF2B21CA4BE7D918D726464807022100BF694AEFECBBDBC1EBF3C253C0A8639377D0515D4E8A9010B07461A4C5503493");
// const char hstring_cert[] = "300x8201443081EBA00302010202086F51FF8D8C545AE9300A06082A8648CE3D0403023017311530130603550403130C534943532054455354204341301E170D3135303631353037353332335A170D3138303631343037353332335A3015311330110603550403130A554450205365727665723059301306072A8648CE3D020106082A8648CE3D030107034200043E4A25E3BFF3463B0E3A06DBF42DE2AE694EA58422F815F558A55979DC6DC65BCC1298C8BDD949346A1B4CCEE86340376B7A007C2CB5D76B29081B7608664751A3233021301F0603551D230418301680144C3C3859EA14F1D9FB9D1A2B25DD436030E25488300A06082A8648CE3D0403020348003045022062589EB3D264EA6E3803C86D07A56D27E8FAB4EF2B21CA4BE7D918D726464807022100BF694AEFECBBDBC1EBF3C253C0A8639377D0515D4E8A9010B07461A4C5503493";
	// const char hexstring_cert[] = "3bda5b6c05595de5642bf613f8d1afd4d4a80759";


	PRINTF("token %d \n", payload->ptr);
	return payload->ptr;
}*/

#endif

uint16_t generate_dummy_access_token(cbor_data *payload_bytes, uint8_t mode) {
 	uint32_t time = 3600;
 	uint32_t grant_type = 10; //password=0, authorization_code=1, client_credentials=2, resfresh_token=3;
 	switch(mode){
 		case 0:
 		LOG_INFO("\n\nGenerating Access Token with no dtls\n\n");
 			return generate_access_token_no_dtls(payload_bytes,
								 "subject",
								 "coap://example.com",
								 time,
								 "a_client_id",
								 "read_scope",
								 grant_type,
								 "an_encoded_access_token",
								 "P-o-P",
								 "client_username",
								 "client_password",
								 "coap");
#if WITH_DTLS
 		case 1:
 			LOG_INFO("\n\nGenerating Access Token for PSK\n\n");
 			return generate_access_token_for_psk(payload_bytes,
								 "subject",
								 "coap://example.com",
								 time,
								 "a_client_id",
								 "read_scope",
								 grant_type,
								 "an_encoded_access_token",
								 "P-o-P",
								 "client_username",
								 "client_password",
								 "coap_dtls");
/* 		case 2:
 			printf("\nGenerating Access Token for RPK\n");
 			return generate_access_token_for_rpk(payload_bytes,
								 "subject",
								 "coap://example.com",
								 time,
								 "a_client_id",
								 "read_scope",
								 grant_type,
								 "an_encoded_access_token",
								 "P-o-P",
								 "client_username",
								 "client_password",
								 "coap_dtls");*/

#endif
		default:
			return 0;
 	     }


}



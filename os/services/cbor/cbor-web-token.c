#include "cbor-web-token.h"
#include "cose-encoder.h"

#include <stdlib.h>
#include <stdio.h>

#include "sys/log.h"

#define LOG_MODULE "Test"
#define LOG_LEVEL LOG_LEVEL_INFO

#define  DISABLE_PRINTF_CBOR   0
int8_t add_generic_claim(cbor_web_token *cbor_wtoken, uint8_t *claim,
						enum cbor_encoded_claim_key claim_key, uint8_t len) {

	if(cbor_wtoken->claim_count >= cbor_wtoken->max_count) {
		return 0;
	} else {
		cbor_wtoken->claim_key[cbor_wtoken->claim_count] = claim_key;
		cbor_wtoken->claim[cbor_wtoken->claim_count] = (uint8_t *)malloc(len*sizeof(uint8_t));
		memcpy(cbor_wtoken->claim[cbor_wtoken->claim_count], claim, len);
		//cbor_wtoken->claim[cbor_wtoken->claim_count][len] = '\0';
		LOG_INFO_("%d -> %s\n", cbor_wtoken->claim_count, cbor_wtoken->claim[cbor_wtoken->claim_count]);
		cbor_wtoken->claim_count++;
		return 1;
	}
}



void integer2bytestring(uint32_t data, uint8_t num_bytes, uint8_t *dstr) {

	uint8_t v, i;
	for(i=num_bytes; i>=1; i--) {
		v = (uint8_t) (data%256);
		data = (uint32_t) (data - v) / 256;
		dstr[i-1] = v;
	}
	//data = (uint32_t)dstr[0]*16777216 + (uint32_t)dstr[1]*65536 + (uint32_t)dstr[2]*256 + (uint32_t)dstr[3];
	//("%lu -> %u, %u, %u, %u\n", data, dstr[0], dstr[1], dstr[2], dstr[3]);
}


uint32_t bytestring2integer(uint8_t num_bytes, uint8_t *dstr) {

	uint32_t data;
	uint8_t  i;

	data  = (uint32_t) dstr[0];
	for(i=1; i<num_bytes; i++) {
		data = (data << 8);
		data = data + (uint32_t) dstr[i];
	}

	return data;
}

void initiate_cbor_web_token(cbor_web_token *cbor_wtoken, int8_t num_claims) {

	cbor_wtoken->claim_key = (uint8_t *)malloc(num_claims*sizeof(uint8_t));
	cbor_wtoken->claim = (uint8_t **)malloc(num_claims*sizeof(uint8_t));

	cbor_wtoken->claim_count = 0;
	cbor_wtoken->max_count = num_claims;
}




void encode_cwt_directly(cbor_data *data, uint8_t claim_key, uint8_t *claim) {
	encode_unsigned_int(data, claim_key);
#if DISABLE_PRINTF_CBOR
	printf("\n%d\n",claim_key );
#endif
	switch(claim_key) {
		case ISS:
			//encode_text_string(data, (char *)claim);
//			printf("\nEncoding ISS\n");
		case SUB:
			//encode_text_string(data, (char *)claim);
//			printf("\nEncoding SUB\n");
			//break;
		case AUD:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING AUD\n");
			//break;
		
			//break;
		case CLIENT_ID:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING CLIENT_ID\n");
			//break;
		case SCOPE:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING SCOPE\n");
			//break;
		case ACCESS_TOKEN:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING ACCESS_TOKEN\n");
//          	break;
		case TOKEN_TYPE:		 	
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING TOKEN_TYPE\n");
//			break;
		case USERNAME:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING USERNAME\n");
//			break;
		case PASSWORD:
			//encode_text_string(data, (char *)claim);
//			printf("\nENCODING PASSWORD\n");
//			break;
		case CNF:
			//encode_text_string(data, (char *)claim);
	//		printf("\nENCODING CNF\n");
//			break;
		case PROFILE:
		 	encode_text_string(data, (char *)claim);
#if DISABLE_PRINTF_CBOR
		 	printf("\nENCODING PROFILE\n");
#endif
		 	break;

		
		case EXP:
			//encode_text_string(data, (char *)claim);
	//		printf("\nENCODING EXP\n");
		case NBF:
	//		printf("\nENCODING NBF\n");
		case IAT:
	//		printf("\nENCODING IAT\n");
		case CTI:
	//		printf("\nENCODING CTI\n");
		case GRANT_TYPE:
			encode_major_type_six(data, 1, claim);
			printf("\nENCODING GRANT_TYPE\n");
			break; // TODO find a better way to see if the key is in enum


		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the encode_cwt_directly function\n");
#endif
			LOG_INFO_("ENCODING ERROR:  unknown claim key: %d\n", claim_key);
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif
	}
}



void encode_struct_in_cwt_directly(cbor_data *data, uint8_t claim_key, uint8_t *claim, uint32_t cnf_len) {
	encode_unsigned_int(data, claim_key);
#if DISABLE_PRINTF_CBOR
	printf("\n%d\n",claim_key );
#endif
	switch(claim_key) {
		case CNF:
			encode_byte_string(data, (uint8_t *)claim, cnf_len);
#if DISABLE_PRINTF_CBOR
		printf("\nENCODING PROFILE\n");
#endif
			break;
		default:
			LOG_INFO_("ENCODING ERROR:  struct claim key: %d\n", claim_key);
	}
}

void encode_cnf(cbor_data *data, uint8_t cnf_key, uint8_t *method) {
	encode_unsigned_int(data, cnf_key);
#if DISABLE_PRINTF_CBOR
	printf("\n%d\n",cnf_key );
#endif	
	switch(cnf_key) {
		case COSE_ENCRYPTED:
		  	// encode_text_string(data, (char *)method);
#if DISABLE_PRINTF_CBOR
			printf("\nENCODING COSE_ENCRYPTED in encode_cnf\n");
#endif
 //         	break;
		case CNF_KEY_ID:
#if DISABLE_PRINTF_CBOR
		  	// encode_text_string(data, (char *)method);
			printf("\nENCODING CNF_KEY_ID in encode_cnf\n");
#endif
//          	break;
		//case KMP:

		//case IPSEC_STRUC:

		case COSE_KEY:
			encode_text_string(data, (char *)method);
#if DISABLE_PRINTF_CBOR
			printf("\nENCODING COSE_KEY in encode_cnf\n");
#endif
         	break;
		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the encode_cnf function\n");
#endif
			LOG_INFO_("ENCODING ERROR:  unknown cnf key: %d\n", cnf_key);
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif
	}
}

void encode_struc_in_cnf(cbor_data *data, uint8_t cnf_key, uint8_t *method, uint32_t struct_len) {
	encode_unsigned_int(data, cnf_key);
	cbor_data temp_data;
	uint8_t data_bytes[300];
	temp_data.buf = data_bytes;
	temp_data.ptr = 0;
#if DISABLE_PRINTF_CBOR
	printf("\n%d\n",cnf_key );
#endif
	switch(cnf_key) {
		case COSE_KEY:
			wrapin_cose_envelope(&temp_data, COSE_ENCRYPT0, (uint8_t *)method, struct_len);

			// unwrap_cose_envelope(&data, COSE_ENCRYPT0, data->buf, struct_len);
			encode_byte_string(data, data_bytes, temp_data.ptr);
			// encode_byte_string(data, (uint8_t *)method, 34);
  //        	break;
			LOG_INFO_("cose len received is %lu and after enc is %lu\n", struct_len,temp_data.ptr);
#if DISABLE_PRINTF_CBOR
			printf("\nENCODING encode_struc_in_cnf\n");
#endif
			// encode_byte_string(data, (uint8_t *)method, struct_len);
         	break;
		/*case IPSEC_STRUC:
			// PRINTF("ipsec len received is %d\n",struct_len);

			// encode_byte_string(data, (uint8_t *)method, 86);
  //        	break;
			encode_byte_string(data, (uint8_t *)method, struct_len);
         	break;*/
		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the encode_struc_in_cnf function\n");
#endif
			LOG_INFO_("ENCODING ERROR:  unknown cnf struct: %d\n", cnf_key);
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif
	}
}

void encode_cose_key(cbor_data *data, uint8_t ck_key, char *method) {
	encode_unsigned_int(data, ck_key);
	printf("\n%d\n",ck_key );
	switch(ck_key) {
		case COSE_KEY_TYPE:
		  	encode_text_string(data, method);
#if DISABLE_PRINTF_CBOR
		  	printf("\nENCODING COSE_KEY_TYPE in COSE_KEY \n");
#endif
         	break;

		case COSE_KEY_ID:
		  	encode_text_string(data, method);
#if DISABLE_PRINTF_CBOR
		  	printf("\nENCODING COSE_KEY_ID in COSE_KEY \n");
#endif
         	break;

		case PSK_KEY:
		  	encode_text_string(data, method);
#if DISABLE_PRINTF_CBOR
		  	printf("\nENCODING PSK_KEY in COSE_KEY \n");
#endif
         	break;
//	 	case COSE_KEY_CRV:
//		        encode_text_string(data, method);
//		break;
//		case COSE_KEY_X:
//			encode_text_string(data, method);
//		break;
//		case COSE_KEY_Y:
//			encode_text_string(data, method);
//		break;
//		case ALG:
//			encode_text_string(data, method);
//		break;
		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the encode_cose_key function\n");
#endif
			LOG_INFO_("ENCODING ERROR: unknown COSE_Key key: %d\n", ck_key);
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif
 }
}
//void encode_ipsec(cbor_data *data, uint8_t ipsec_key, uint8_t *method) 

void encode_cbor_web_token(cbor_data *data, cbor_web_token *cbor_wtoken) {

	uint8_t i;

	encode_map_array(data, cbor_wtoken->claim_count);

	for(i=0; i<cbor_wtoken->claim_count; i++) {
		encode_cwt_directly(data, cbor_wtoken->claim_key[i], cbor_wtoken->claim[i]);
	}
}

#if WITH_DTLS
void decode_cose_key(cbor_data *data, dtls_channel *new_dtls_channel) {
	uint16_t len;
	uint8_t  key;
	uint8_t  i;

	uint8_t claim[30];

	len = (uint16_t)decode_map_array(data);

	// PRINTF("\n\tcose_key{ \n");

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);

		switch(key) {
		case COSE_KEY_TYPE:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\t\tkty: %s\n", claim);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING COSE_KEY_TYPE in decode_cose_key \n");
#endif
         	break;
		case COSE_KEY_ID:
		  	decode_text_string(data, (char *)claim);
		  	memcpy(new_dtls_channel->id, (char *)claim, sizeof(new_dtls_channel->id));
		  	LOG_INFO_("\t\t\tkid: %*.s\n",sizeof(new_dtls_channel->id), new_dtls_channel->id);
			LOG_INFO_("\t\t\tkid: %s\n", claim);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING COSE_KEY_ID in decode_cose_key \n");
#endif
         	break;

		case PSK_KEY:
		  	decode_text_string(data, (char *)claim);
		  	memcpy(new_dtls_channel->key, (char *)claim, sizeof(new_dtls_channel->key));
		  	LOG_INFO_("\t\t\tkid: %*.s\n",sizeof(new_dtls_channel->key), new_dtls_channel->key);
			LOG_INFO_("\t\t\tkey: %s\n",claim);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING PSK_KEY in decode_cose_key \n");
#endif
         	break;
//		case COSE_KEY_CRV:
//		        decode_text_string(data, (char *)claim);
//			PRINTF("\t\t\tcrv: %s\n",claim);
//		break;
//		case COSE_KEY_X:
//			decode_text_string(data, (char *)claim);
//			PRINTF("\t\t\tx: %s\n",claim);
//		break;
//		case COSE_KEY_Y:
//			decode_text_string(data, (char *)claim);
//			PRINTF("\t\t\ty: %s\n",claim);
//		break;
		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the encode_cose_key function\n");
#endif
			LOG_INFO_("DECODING ERROR: unknown COSE_Key value\n");
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif

		}
	}
	// PRINTF("\n\t} //cose_key \n");
}


void decode_cnf(cbor_data *data, dtls_channel *new_dtls_channel) {

	uint16_t len;
	uint8_t  key;
	uint8_t  i;

	uint8_t claim[40];

//	uint8_t ipsec_bytes[256];
//	uint16_t ipsec_len;
//	cbor_data ipsec_payload;

	uint8_t cose_key_bytes[256];
	uint32_t cose_key_len;
	cbor_data cose_key_payload;
	len = (uint16_t)decode_map_array(data);

	// PRINTF("\n\tcose_key{ \n");

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);

		uint8_t *data_bytes;

		switch(key) {

		case COSE_ENCRYPTED:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\tCOSE_Encrypted: %s\n", claim);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING COSE_ENCRYPTED in decode_cnf \n");
#endif
         	break;
		case CNF_KEY_ID:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\tCNF_KEY_ID: %s\n", claim);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING CNF_KEY_ID in decode_cnf \n");
#endif
         	break;
		case COSE_KEY:
		  	LOG_INFO("\t\tCOSE_Key:{\n");
			cose_key_len = decode_byte_string(data, cose_key_bytes);
			cbor_data temp_data;
			temp_data.buf = cose_key_bytes;
			temp_data.ptr = 0;
			LOG_INFO_("%lu\n",cose_key_len);
			data_bytes = (uint8_t*)malloc(sizeof(data_bytes) * cose_key_len);
			unwrap_cose_envelope(&temp_data, COSE_ENCRYPT0, data_bytes, cose_key_len);

 			cose_key_payload.buf = data_bytes;
 			cose_key_payload.ptr = 0;

			decode_cose_key(&cose_key_payload,new_dtls_channel);
#if DISABLE_PRINTF_CBOR
			printf("\nDECODING COSE_KEY in decode_cnf \n");
#endif
			LOG_INFO("\t\t}\n");
			break;

		default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the decode_cnf function\n");
#endif
			LOG_INFO_("DECODING ERROR: unknown cnf value\n");
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif

		}
	}
	// PRINTF("\n\t} //cose_key \n");
}

void decode_cbor_web_token(cbor_data *data, uint8_t *claim, dtls_channel *new_dtls_channel) {

	uint16_t len;
	uint8_t  key;
	uint32_t time;
	uint8_t  i;
	// uint8_t claim[950]; // old value 30
// do the same
	// uint8_t cnf_bytes[256];
	// uint16_t cnf_len;
	// cbor_data cnf_payload;

	len = (uint16_t)decode_map_array(data);

	LOG_INFO_("\nCWT: %u claims\n", len);

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);
#if DISABLE_PRINTF_CBOR
		printf("\n%d\n",key );
#endif
		switch(key) {
			case ISS:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tiss: %s\n", claim);
//				printf("DECODING ISS in decode_cbor_web_token\n");
				break;
			case SUB:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tsub: %s\n", claim);
//				printf("DECODING SUB in decode_cbor_web_token\n");
				break;
			case AUD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\taud: %s\n", claim);
//				printf("DECODING AUD in decode_cbor_web_token\n");
				break;
			case EXP:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\n\texp: %lu\n", time);
//				printf("DECODING EXP in decode_cbor_web_token\n");
				break;
			case NBF:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\n\tnbf: %lu\n", time);
//				printf("DECODING NBF in decode_cbor_web_token\n");
				break;
			case IAT:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\n\tiat: %lu\n", time);
//				printf("DECODING IAT in decode_cbor_web_token\n");
				break;			
			case CTI:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tcti: %s\n", claim);
//				printf("DECODING CTI in decode_cbor_web_token\n");
				break;
			case CLIENT_ID:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tclient_id: %s\n", claim);
//				printf("DECODING CLIENT_ID in decode_cbor_web_token\n");
				break;
			case SCOPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tscope: %s\n", claim);
//				printf("DECODING SCOPE in decode_cbor_web_token\n");
				break;
			case GRANT_TYPE:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\n\tgrant_type: %lu\n", time);
//				printf("DECODING GRANT_TYPE in decode_cbor_web_token\n");
				break;
			case ACCESS_TOKEN:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\taccess_token: %s\n", claim);
//				printf("DECODING ACCESS_TOKEN in decode_cbor_web_token\n");
				break;
			case TOKEN_TYPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\ttoken_type: %s\n", claim);
//				printf("DECODING TOKEN_TYPE in decode_cbor_web_token\n");
				break;
			case USERNAME:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tusername: %s\n", claim);
//				printf("DECODING USERNAME in decode_cbor_web_token\n");
				break;
			case PASSWORD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tpassword: %s\n", claim);
//				printf("DECODING PASSWORD in decode_cbor_web_token\n");
				break;
			case CNF:
				LOG_INFO_("\n\tcnf:{\n");
				decode_text_string(data, (char *)claim);
//				printf("DECODING CNF in decode_cbor_web_token\n");
				break;
			case PROFILE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\n\tprofile: %s\n", claim);
//				printf("DECODING PROFILE in decode_cbor_web_token\n");
				break;

#if DTLS_PSK

///// CNF
		case COSE_ENCRYPTED:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\n\t\tCOSE_Encrypted: %s\n", claim);
//			printf("DECODING COSE_ENCRYPTED in decode_cbor_web_token\n");
         	break;
		case CNF_KEY_ID:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\n\t\tCNF_KEY_ID: %s\n", claim);
//			printf("DECODING CNF_KEY_ID in decode_cbor_web_token\n");
         	break;	


		case COSE_KEY:
		  	LOG_INFO("\n\t\tCOSE_Key:{\n");
		  	decode_text_string(data, (char *)claim);
//		  	printf("DECODING COSE_KEY in decode_cbor_web_token\n");
		  	break;
		case COSE_KEY_TYPE:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\n\t\t\tkty: %s\n", claim);
			break;
		case COSE_KEY_ID:
		  	decode_text_string(data, (char *)claim);
			//new_dtls_channel->id = (char *)claim;
		  	memcpy(new_dtls_channel->id, (char *)claim, sizeof(new_dtls_channel->id));
			LOG_INFO_("\n\t\t\tkid: %s\n", new_dtls_channel->id);
			break;
//			printf("DECODING COSE_KEY_ID in decode_cbor_web_token\n");

		
//			printf("DECODING COSE_KEY_TYPE in decode_cbor_web_token\n");
		case PSK_KEY:
		  	decode_text_string(data, (char *)claim);
		  	memcpy(new_dtls_channel->key, (char *)claim, sizeof(new_dtls_channel->key));
			//new_dtls_channel->key = (char *)claim;
			LOG_INFO_("\t\t\tkey: %s\n", new_dtls_channel->key);
//			printf("\nDECODING PSK_KEY in decode_cbor_web_token\n");
			LOG_INFO("\t\t}\n");
         	break;
	


		
			// cose_key_len = decode_byte_string(data, cose_key_bytes);
			// cbor_data temp_data;
			// temp_data.buf = cose_key_bytes;
			// temp_data.ptr = 0;
			// PRINTF("%d\n",cose_key_len);
			// data_bytes = (uint8_t*)malloc(sizeof(data_bytes) * cose_key_len);
			// unwrap_cose_envelope(&temp_data, COSE_ENCRYPT0, data_bytes, cose_key_len);

 		// 	cose_key_payload.buf = data_bytes;
 		// 	cose_key_payload.ptr = 0;

			// decode_cose_key(&cose_key_payload, new_ipsec_sa);
			// PRINTF("\t\t}\n");
		
         	       	


		
#endif
////
			default:
#if DISABLE_PRINTF_CBOR
			printf("\n-----------------------------------------------------------------\n");
			printf("has the error on the full decode_cbor_web_token function DTLS_PSK situation 1111111111111111\n");
#endif
			LOG_INFO_("DECODING ERROR: unknown claim %d\n",key );
#if DISABLE_PRINTF_CBOR
			printf("-----------------------------------------------------------------\n");
#endif
	}
  }
}

#else
void decode_cbor_web_token(cbor_data *data, uint8_t * claim, dtls_channel *new_dtls_channel) {

	uint16_t len;
	uint8_t  key;
	uint32_t time;
	uint8_t  i;
	// uint8_t claim[950]; // old value 30
// do the same
	// uint8_t cnf_bytes[256];
	// uint16_t cnf_len;
	// cbor_data cnf_payload;

	len = (uint16_t)decode_map_array(data);

	LOG_INFO_("\nCWT: %u claims\n", len);

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);
		switch(key) {
			case ISS:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tiss: %s\n", claim);
				break;
			case SUB:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tsub: %s\n", claim);
				break;
			case AUD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\taud: %s\n", claim);
				break;
			case EXP:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\texp: %lu\n", time);
				break;
			case NBF:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tnbf: %lu\n", time);
				break;
			case IAT:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tiat: %lu\n", time);
				break;			case CTI:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tcti: %s\n", claim);
				break;
			case CLIENT_ID:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tclient_id: %s\n", claim);
				break;
			case SCOPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tscope: %s\n", claim);
				break;
			case GRANT_TYPE:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tgrant_type: %lu\n", time);
				break;
			case ACCESS_TOKEN:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\taccess_token: %s\n", claim);
				break;
			case TOKEN_TYPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\ttoken_type: %s\n", claim);
				break;
			case USERNAME:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tusername: %s\n", claim);
				break;
			case PASSWORD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tpassword: %s\n", claim);
				break;
			case CNF:
				LOG_INFO("\tcnf:{\n");
				decode_text_string(data, (char *)claim);
				break;
			case PROFILE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tprofile: %s\n", claim);
				break;
////
			default:
				LOG_INFO_("DECODING ERROR: unknown claim %d\n",key );
		}
	}
}

void decode_cose_key_no_dtls(cbor_data *data) {

	uint16_t len;
	uint8_t  key;
	uint8_t  i;

	uint8_t claim[100];

	len = (uint16_t)decode_map_array(data);

	// PRINTF("\n\tcose_key{ \n");

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);

		switch(key) {
		case COSE_KEY_TYPE:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\t\tkty: %s\n", claim);
         	break;
		case COSE_KEY_ID:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\t\tkid: %s\n", claim);
         	break;
		case PSK_KEY:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO_("\t\t\tkey: %s\n",claim);
         	break;
		default:
			LOG_INFO("DECODING ERROR: unknown COSE_Key value\n");

		}
	}
	// PRINTF("\n\t} //cose_key \n");
}
//void decode_ipsec_no_ipsec(cbor_data *data)

void decode_cnf_no_dtls(cbor_data *data) {

	uint16_t len;
	uint8_t  key;
	uint8_t  i;

	uint8_t claim[40];

	//uint8_t ipsec_bytes[256];
	//uint16_t ipsec_len;
	//cbor_data ipsec_payload;

	uint8_t cose_key_bytes[256];
	cbor_data cose_key_payload;
	len = (uint16_t)decode_map_array(data);

	// PRINTF("\n\tcose_key{ \n");

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);

		switch(key) {
		case COSE_KEY:
		  	LOG_INFO("\t\tCOSE_Key:{\n");
			uint32_t cose_key_len = decode_byte_string(data, cose_key_bytes);
 			cose_key_payload.buf = cose_key_bytes;
 			cose_key_payload.ptr = 0;
			decode_cose_key_no_dtls(&cose_key_payload);
			LOG_INFO_("%lu\n",cose_key_len);
			LOG_INFO("\t\t}\n");
			break;
		case COSE_ENCRYPTED:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO("\t\tCOSE_Encrypted: %s\n", claim);
         	break;
		case CNF_KEY_ID:
		  	decode_text_string(data, (char *)claim);
			LOG_INFO("\t\tkid: %s\n", claim);
         	break;
		/*case IPSEC_STRUC:
				PRINTF("\t\tipsec:{\n");
				ipsec_len = decode_byte_string(data, ipsec_bytes);
	 			ipsec_payload.buf = ipsec_bytes;
	 			ipsec_payload.ptr = 0;
				decode_ipsec_no_ipsec(&ipsec_payload);
				PRINTF("\t\t}\n");
				break;
		case KMP:
			decode_text_string(data, (char *)claim);
			PRINTF("\t\tkmp: %s\n", claim);
         	break;*/
		default:
			LOG_INFO("DECODING ERROR: unknown cnf value\n");

		}
	}
	// PRINTF("\n\t} //cose_key \n");
}

void decode_cbor_web_token_no_dtls(cbor_data *data) {

	uint16_t len;
	uint8_t  key;
	uint32_t time;
	uint8_t  i;
	uint8_t claim[40]; // old value 30

	uint8_t cnf_bytes[256];
	uint16_t cnf_len;
	cbor_data cnf_payload;

	len = (uint16_t)decode_map_array(data);

	LOG_INFO_("\nCWT: %u claims\n", len);

	for(i=0; i<len; i++) {
		key = (uint8_t) decode_unsigned_int(data);
		switch(key) {
			case ISS:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tiss: %s\n", claim);
				break;
			case SUB:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tsub: %s\n", claim);
				break;
			case AUD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\taud: %s\n", claim);
				break;
			case EXP:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\texp: %lu\n", time);
				break;
			case NBF:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tnbf: %lu\n", time);
				break;
			case IAT:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tiat: %lu\n", time);
				break;			
			case CTI:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tcti: %s\n", claim);
				break;
			case CLIENT_ID:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tclient_id: %s\n", claim);
				break;
			case SCOPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tscope: %s\n", claim);
				break;
			case GRANT_TYPE:
				decode_major_type_six(data, 1, claim);
				time = bytestring2integer(4, claim);
				LOG_INFO_("\tgrant_type: %lu\n", time);
				break;
			case ACCESS_TOKEN:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\taccess_token: %s\n", claim);
				break;
			case TOKEN_TYPE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\ttoken_type: %s\n", claim);
				break;
			case USERNAME:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tusername: %s\n", claim);
				break;
			case PASSWORD:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tpassword: %s\n", claim);
				break;
			case CNF:
				LOG_INFO("\tcnf:{\n");
				cnf_len = decode_byte_string(data, cnf_bytes);
				LOG_INFO_("cnf len : %d\n", cnf_len);
	 			cnf_payload.buf = cnf_bytes;
	 			cnf_payload.ptr = 0;
				decode_cnf_no_dtls(&cnf_payload);
				LOG_INFO("\t}\n");
				break;
			case PROFILE:
				decode_text_string(data, (char *)claim);
				LOG_INFO_("\tprofile: %s\n", claim);
				break;
			default:
				LOG_INFO_("DECODING ERROR: unknown claim %d\n",key );
		}
	}
}
#endif

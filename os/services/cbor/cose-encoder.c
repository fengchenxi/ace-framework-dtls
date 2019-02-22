#include "cose-encoder.h"

#include "lib/ccm-star.h"

#include "stdlib.h"

//#include "ecc/ecc.h"


#define MAX_HEADER_BYTE_LEN		40

/*#ifdef COSE_SIGN1


#else
#ifdef COSE
#else
#endif
#endif*/

//#define WORDS_32_BITS		1





/**** generic definitions ***************/

#define SECURITY_SUIT		10



/**** COSE header parameters ******/
static uint8_t algo;

static uint8_t crit;

static uint8_t key_id[32];

static uint8_t init_vec[32];

static uint8_t par_init_vec[16];



/**** definitions and varibles for SIGN ***********/

//#define WORDS_16_BITS		1

//#define SIG_LEN				sizeof(u_word)*NUMWORDS

//static ecc_point_a public_key;

//static u_word private_key[NUMWORDS];


/**** definitions and variables for ENCRYPTION and MAC (in CCM mode) ******/

#define NONCE_SIZE			13

#define TAG_LEN				16

const struct ccm_star_driver CCM_STAR;

const unsigned char COSE_SECRET[] = "CHAYAN@SICS##KEY";

uint8_t nonce[NONCE_SIZE] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0x20, 0x21, 0x22, 0x23};
uint8_t a[2] = {0x10, 0x20};
uint8_t a_len = 2;
int forward = 1;



/*************************************************************************************/
/*************************** private functions ***************************************/
/*************************************************************************************/


/**
 *
 */
uint8_t decode_cose_header_map_array(cbor_data *data) {

	uint8_t i;
	uint8_t len;
	uint8_t label;

	/* number of parameters in the header map */
	len = (uint8_t) decode_map_array(data);

	/* get the elements from the unprotected header */
	for(i=0; i<len; i++) {
		label = (uint8_t) decode_unsigned_int(data);

		switch(label) {
			case ALG:
				algo = (uint8_t) decode_unsigned_int(data);
				printf("\tAlgo\n");
				break;
			case CRIT:
				crit = (uint8_t) decode_unsigned_int(data);
				printf("\tCritial id\n");
				break;
			//case CON_TYPE:
			//	break;
			case KEY_ID:
				decode_byte_string(data, key_id);
				printf("\tKey ID\n");
				break;
			case IV:
				decode_byte_string(data, init_vec);
				printf("\tIV\n");
				break;
			case PAR_IV:
				decode_byte_string(data, par_init_vec);
				printf("\tPartial IV\n");
				break;
			//case CNT_SIGN:
			//	break;
			default:
				printf("unknown cose header label\n");
				return 0;
		}
	}

	return 1;
}


/**
 *
 */
//uint8_t encode_cose_sign1_header(cbor_data *data, uint8_t *protected_bytes,
//		uint8_t *payload_bytes, uint16_t payload_len) {

	/** the ordering , i.e., protected header map, signature calculation, and
	 * unprotected header map has to be maintained, because, the protected header
	 * map is used in signature calculation, and the rr value generated in signature
	 * calculation is sent as IV in unprotected header */

//	int8_t j;

	/**** encode protected header map ********/
	/* number of parameters in the protected header */
//	cbor_data cbd;
//	cbd.buf = protected_bytes;
//	cbd.ptr = 0;
//	encode_map_array(&cbd, 1);

	/* add the algorithm as the protected header (key & value) */
//	encode_unsigned_int(&cbd, ALG);
//	encode_unsigned_int(&cbd, SECURITY_SUIT);

	/* encode the protected header map as byte string */
//	uint8_t p_hdr_len = (uint8_t)cbd.ptr;
//	encode_byte_string(data, protected_bytes, p_hdr_len);


	/**** generate the signature ***********/
	/* attach the payload with the protected header to calculate
	 * the signature on the whole content */
//	memcpy(&protected_bytes[p_hdr_len], payload_bytes, payload_len);

//	new_ecc_init();
//	ecc_generate_private_key(private_key);
//	ecc_generate_public_key(private_key, &public_key);

	/* generate the signature */
//	u_word signature[NUMWORDS];
//	u_word rr[NUMWORDS];
//	ecc_generate_signature(private_key, protected_bytes, p_hdr_len+payload_len, signature, rr);

	/* attach the signature at the end of the protected header (in the protected bytes) */
//	for(j = 0; j<NUMWORDS; j++) {
//		encode_following_bytes(&cbd, signature[j], sizeof(u_word));
//	}


	/**** encode unprotected header map **********/
	/* number of parameters in the unprotected header */
//	encode_map_array(data, 1);

	/* add the nonce as initialization vector in the unprotected header (key & value) */
//	encode_unsigned_int(data, IV);
//	encode_byte_string_length_only(data, sizeof(u_word)*NUMWORDS);
//	for(j = 0; j<NUMWORDS; j++) {
//		encode_following_bytes(data, rr[j], sizeof(u_word));
//	}


	/**** return the protected header length (in protected bytes) *****/
//	return p_hdr_len;
//}

/**
 *
 */
uint8_t encode_cose_encrypt0_header(cbor_data *data, uint8_t *protected_bytes,
		uint8_t *payload_bytes, uint16_t payload_len) {

	/**** encode protected header map ********/
	/* number of parameters in the protected header */
	cbor_data cbd;
	cbd.buf = protected_bytes;
	cbd.ptr = 0;
	encode_map_array(&cbd, 1);

	/* add the algorithm identifier in the protected header (key & value) */
	encode_unsigned_int(&cbd, ALG);
	encode_unsigned_int(&cbd, SECURITY_SUIT);

	/* encode the protected header map as byte string */
	uint8_t p_hdr_len = (uint8_t)cbd.ptr;
	encode_byte_string(data, protected_bytes, p_hdr_len);


	/**** encrpyt the data (protected header + payload) *****/
	uint8_t mac_tag[TAG_LEN];
	memcpy(&protected_bytes[p_hdr_len], payload_bytes, payload_len);
	CCM_STAR.set_key(COSE_SECRET);
	CCM_STAR.aead(nonce, protected_bytes, p_hdr_len+payload_len, a, a_len, mac_tag, TAG_LEN, forward);


	/**** encode unprotected header map **********/
	/* number of parameters in the unprotected header */
	encode_map_array(data, 1);

	/* add the nonce as initialization vector in the unprotected header (key & value) */
	encode_unsigned_int(data, IV);
	encode_byte_string(data, nonce, NONCE_SIZE);


	/**** return the protected header length (in protected bytes) *****/
	return p_hdr_len;
}

/**
 *
 */
uint8_t encode_cose_mac0_header(cbor_data *data, uint8_t *protected_bytes,
		uint8_t *payload_bytes, uint16_t payload_len) {

	/**** encode protected header map ********/
	/* number of parameters in the protected header */
	cbor_data cbd;
	cbd.buf = protected_bytes;
	cbd.ptr = 0;
	encode_map_array(&cbd, 1);

	/* add the algorithm identifier in the protected header (key & value) */
	encode_unsigned_int(&cbd, ALG);
	encode_unsigned_int(&cbd, SECURITY_SUIT);

	/* encode the protected header map as byte string */
	uint8_t p_hdr_len = (uint8_t)cbd.ptr;
	encode_byte_string(data, protected_bytes, p_hdr_len);


	/**** calculate MAC for the data (protected header + payload) */
	uint8_t mac_tag[TAG_LEN];
	memcpy(&protected_bytes[p_hdr_len], payload_bytes, payload_len);
	CCM_STAR.set_key(COSE_SECRET);
	CCM_STAR.aead(nonce, protected_bytes, p_hdr_len+payload_len, a, a_len, mac_tag, TAG_LEN, forward);
	memcpy(&protected_bytes[p_hdr_len], mac_tag, TAG_LEN);


	/**** encode unprotected header map **********/
	/* number of parameters in the unprotected header */
	encode_map_array(data, 1);

	/* add the nonce as initialization vector in the unprotected header (key & value) */
	encode_unsigned_int(data, IV);
	encode_byte_string(data, nonce, NONCE_SIZE);


	/**** return the protected header length (in protected bytes) *****/
	return p_hdr_len;
}

/**
 *
 */
/*uint8_t verify_cose_sign1(cbor_data *data, uint8_t *protected_bytes, uint16_t p_bytes_len) {

	u_word signature[NUMWORDS];
	u_word rx[NUMWORDS];
	uint8_t l,i,k;

	// extract the signature and initialization vector 
	l = (uint8_t) decode_byte_string_length_only(data);
	k = 0;
	for(l=0; l<NUMWORDS; l++) {
		signature[l] = (u_word) decode_following_bytes(data, sizeof(u_word));

		rx[l] = (u_word) init_vec[k++];
		for(i=1; i<sizeof(u_word); i++) {
			rx[l] = (rx[l] << 8) + (u_word) (init_vec[k++]);
		}
	}

	// verify the signature 
	if(ecc_check_signature(&public_key, protected_bytes, p_bytes_len, signature, rx)) {
		printf("4. Signature verified OK\n");
		return 1;
	} else {
		printf("Signature not verified\n");
		return 0;
	}
}*/


/**
 *
 */
void decrypt_cose_encrypt0(uint8_t *protected_bytes, uint16_t p_bytes_len) {


	uint8_t mac_tag[TAG_LEN];

	/* decrypt the protected data */
	CCM_STAR.set_key(COSE_SECRET);
	CCM_STAR.aead(init_vec, protected_bytes, p_bytes_len, a, a_len, mac_tag, TAG_LEN, forward);
	printf("Decryption DONE\n");
}


/**
 *
 */
uint8_t verify_cose_mac0(cbor_data *data, uint8_t *protected_bytes, uint16_t p_bytes_len) {

	uint8_t mac_tag[TAG_LEN];
	uint8_t mac_tag_rx[TAG_LEN];
	uint8_t l;

	/* calculate the MAC on the recevied bytes */
	CCM_STAR.set_key(COSE_SECRET);
	CCM_STAR.aead(init_vec, protected_bytes, p_bytes_len, a, a_len, mac_tag, TAG_LEN, forward);

	/* decode the received MAC */
	l = (uint8_t) decode_byte_string(data, mac_tag_rx);

	/* verify data integrity by comparing the MACs (calculated and received) */
	if(l != TAG_LEN) {
		printf("MAC is not valid\n");
		return 0;
	}
	for(l=0; l<TAG_LEN; l++) {
		if(mac_tag[l] != mac_tag_rx[l]) {
			printf("MAC is not valid\n");
			return 0;
		}
	}
	printf("4. MAC verified OK\n");

	return 1;
}


/*************************************************************************************/
/******************************** public APIs ****************************************/
/*************************************************************************************/

/**
 *
 */
void wrapin_cose_envelope(cbor_data *data, enum cose_type ctype, uint8_t *payload_bytes, uint16_t payload_len) {

	uint8_t protected_bytes[MAX_HEADER_BYTE_LEN + payload_len];
	uint16_t p_hdr_len;

	//if(ctype == COSE_SIGN1) {
		/* encode array length */
		//encode_data_array(data, COSE_SIGN1_ARRAY_LEN);

		/* first and second element: encode the protected and unprotected header info */
		//p_hdr_len = encode_cose_sign1_header(data, protected_bytes, payload_bytes, payload_len);

		/* third element: encode the payload */
		//encode_byte_string(data, payload_bytes, payload_len);

		/* fourth element: encode signature */
		//encode_byte_string(data, &protected_bytes[p_hdr_len], SIG_LEN);
	//}
	//else 
		if(ctype == COSE_ENCRYPT0) {
		/* encode array length */
		encode_data_array(data, COSE_ENCRYPT0_ARRAY_LEN);

		/* first and second element: encode protected and unprotected header info */
		p_hdr_len = encode_cose_encrypt0_header(data, protected_bytes, payload_bytes, payload_len);

		/* third element: encode the encrypted payload */
		encode_byte_string(data, &protected_bytes[p_hdr_len], payload_len);
	}
	else if(ctype == COSE_MAC0) {
		/* encode array length */
		encode_data_array(data, COSE_MAC0_ARRAY_LEN);

		/* first and second element: encode protected and unprotected header info */
		p_hdr_len = encode_cose_mac0_header(data, protected_bytes, payload_bytes, payload_len);

		/* third element: encode the payload */
		encode_byte_string(data, payload_bytes, payload_len);

		/* fourth element: encode MAC tag */
		encode_byte_string(data, &protected_bytes[p_hdr_len], TAG_LEN);
	}
	else {
		printf("Unknown COSE type\n");
	}
}


/**
 *
 */
uint16_t unwrap_cose_envelope(cbor_data *data, enum cose_type ctype, uint8_t *payload_bytes, uint16_t payload_len) {

	uint8_t *p_hdr;
	uint16_t p_hdr_len;

	uint8_t l;


	/**** encode length of the array **********/
	/* protected header, unprotected header, payload, and signature */
	l = (uint8_t) decode_data_array(data);
	/* if the array length is not equal to the specified length, return error */
	//if(ctype == COSE_SIGN1 && l == COSE_SIGN1_ARRAY_LEN) {
	//	printf("\nCOSE_SIGN1: number of array elements %u\n", l);
//	} else 
	if(ctype == COSE_ENCRYPT0 && l == COSE_ENCRYPT0_ARRAY_LEN) {
		printf("\nCOSE_ENCRYPT0: number of array elements %u\n", l);
	} else if(ctype == COSE_MAC0 && l == COSE_MAC0_ARRAY_LEN) {
		printf("\nCOSE_MAC0: number of array elements %u\n", l);
	} else {
		printf("\nIll-formed COSE envelope\n");
		return 0;
	}


	/**** first and second element: protected and unprotected headers *****/
	/* decode protected header */
	printf("1. Protected header\n");
	p_hdr_len = (uint8_t) decode_byte_string_length_only(data);
	if(p_hdr_len > 0) {
		p_hdr = &data->buf[data->ptr];
		decode_cose_header_map_array(data);
	}


	/**** decode unprotected header *****/
	printf("2. Unprotected header\n");
	decode_cose_header_map_array(data);


	/**** third element: the payload ********/
	/* decode the payload */
	payload_len = (uint16_t) decode_byte_string(data, payload_bytes);
	printf("3. Payload of length %u \n", payload_len);


	/**** crypto operation ********/
	uint8_t protected_bytes[p_hdr_len + payload_len];
	/* operation must be done against the received data (protected header + payload) */
	memcpy(protected_bytes, &p_hdr, p_hdr_len);
	memcpy(&protected_bytes[p_hdr_len], payload_bytes, payload_len);

	/* do the crypto operation */
//	if(ctype == COSE_SIGN1) {
//		return verify_cose_sign1(data, protected_bytes, p_hdr_len + payload_len);
//	}
//	else 
	if(ctype == COSE_ENCRYPT0) {
		decrypt_cose_encrypt0(protected_bytes, p_hdr_len + payload_len);
		/* copy the decrypted payload */
		memcpy(payload_bytes, &protected_bytes[p_hdr_len], payload_len);
		return 1;
	}
	else if(ctype == COSE_MAC0) {
		return verify_cose_mac0(data, protected_bytes, p_hdr_len + payload_len);
	}
	else {
		printf("Unknown COSE type\n");
		return 0;
	}
}

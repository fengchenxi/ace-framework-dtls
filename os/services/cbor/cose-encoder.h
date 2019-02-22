#ifndef COSE_ENCODER_H_
#define COSE_ENCODER_H_

#include "cbor-encoder.h"

#define COSE_SIGN1_ARRAY_LEN			4
#define COSE_ENCRYPT0_ARRAY_LEN			3
#define COSE_MAC0_ARRAY_LEN				4



enum cbor_tag {
	TBD1 = 1,
	TBD2 = 2,
	TBD3 = 3,
	TBD4 = 4,
	TBD6 = 6,
	TBD7 = 7
};

enum cose_type {
	COSE_SIGN     = TBD1,	/* unsigned integer */
	COSE_SIGN1    = TBD7,	/* negative integer */
	COSE_ENCRYPT  = TBD2,	/* byte string */
	COSE_ENCRYPT0 = TBD3,	/* text string */
	COSE_MAC      = TBD4,	/* array of data items */
	COSE_MAC0     = TBD6	/* map of pair of data items */
};


/******   COSE common header parameters *************/
enum cose_common_hdr_param {
	ALG 	 = 1,
	CRIT 	 = 2,
	CON_TYPE = 3,
	KEY_ID   = 4,
	IV 		 = 5,
	PAR_IV   = 6,
	CNT_SIGN = 7
};



void wrapin_cose_envelope(cbor_data *data, enum cose_type ctype, uint8_t *payload_bytes, uint16_t payload_len);

uint16_t unwrap_cose_envelope(cbor_data *data, enum cose_type ctype, uint8_t *payload_bytes, uint16_t payload_len);


#endif  /* COSE_ENCODER_H_ */

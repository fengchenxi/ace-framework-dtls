#include "cbor-encoder.h"


#define FALSE_TAG			20

#define TRUE_TAG			21

#define NIL_TAG				22



/********************** private functions ****************************/

/**
 *
 */
void encode_following_bytes(cbor_data *data, uint32_t d, signed char num_bytes) {

	signed char i;
	data->ptr += num_bytes;

	uint8_t v;
	for(i=1; i<=num_bytes; i++) {
		v = (uint8_t) (d%256);
		d = (uint32_t) (d - v) / 256;
		data->buf[data->ptr-i] = v;
	}
}

/**
 *
 */
void encode_generic_data_type(cbor_data *data, uint32_t len, enum major_type MAJOR_TYPE) {

	/* set the major type */
	data->buf[data->ptr] = MAJOR_TYPE;

	if(len < 24) {
		data->buf[data->ptr++] += (uint8_t) len;
	} else if(len <= 0XFF) {
		data->buf[data->ptr++] += 24;
		encode_following_bytes(data, len, 1);
	} else if(len <= 0xFFFF) {
		data->buf[data->ptr++] += 25;
		encode_following_bytes(data, len, 2);
	} else {
		/*** NOTE: Though the standard supports 64 bit integers,
		 * this implementation supports only 32 bit integer ***/
		data->buf[data->ptr++] += 26;
		encode_following_bytes(data, len, 4);
		printf("\n\nencoding has reach the 26 bytes\n\n");
	}
}

/**
 *
 */
uint32_t decode_following_bytes(cbor_data *data, uint8_t num_bytes) {

	uint32_t d;
	uint8_t i;

	d = (uint32_t) data->buf[data->ptr++];
	for(i=1; i<num_bytes; i++) {
		d = (d << 8) + (uint32_t) (data->buf[data->ptr++]);
	}

	return d;
}

/**
 *
 */
uint32_t decode_generic_data_type(cbor_data *data, enum major_type MAJOR_TYPE) {

	uint8_t type = (data->buf[data->ptr] & 0xE0);
	if(type != MAJOR_TYPE) {
		printf("Error: not the expected major type %d\n", MAJOR_TYPE);
		return 0;
	}
	uint8_t add_info = (data->buf[data->ptr++] & 0x1F);
	uint32_t len;

	if(add_info < 24) {
		len = (unsigned long) add_info;
	} else if(add_info == 24) {
		len = decode_following_bytes(data, 1);
	} else if(add_info == 25) {
		len = decode_following_bytes(data, 2);
	} else if(add_info == 26) {
		len = decode_following_bytes(data, 4);
	} else {
		len = 0;
		printf("\n\nCannot decode the following_bytes\n\n");
	}

	return len;
}



/********************** public functions ****************************/

void print_byte_string(uint8_t *bytes, uint16_t len) {

	uint16_t i;
	printf("%d: 0x", len);
	for(i=0; i<len; i++) {
		printf("%.2X", bytes[i]);
	}
	printf("\n");
}

/************** major type 0: usigned int ******************/

/**
 * encode major type 0: usigned int
 */
void encode_unsigned_int(cbor_data *data, uint32_t v) {

	encode_generic_data_type(data, v, MAJOR_TYPE_0);
}

/**
 * decode major type 0: usigned int
 */
uint32_t decode_unsigned_int(cbor_data *data) {

	return decode_generic_data_type(data, MAJOR_TYPE_0);
}

/************** major type 1: negative int ******************/

/**
 * encode major type 1: negative int
 */
void encode_negative_int(cbor_data *data, long v) {

	if(v < 0) {
		uint32_t d = (uint32_t) (-1 - v);
		encode_generic_data_type(data, d, MAJOR_TYPE_1);
	} else {
		encode_generic_data_type(data, (uint32_t)v, MAJOR_TYPE_0);
	}
}

/**
 * decode major type 1: negative int
 */
long decode_negative_int(cbor_data *data) {

	return (long)(-1 - decode_generic_data_type(data, MAJOR_TYPE_1));
}


/************** major type 2: byte string ******************/

/**
 * encode major type 2: byte string
 */
void encode_byte_string_length_only(cbor_data *data, uint32_t len) {

	encode_generic_data_type(data, len, MAJOR_TYPE_2);
}

void encode_byte_string(cbor_data *data, uint8_t *bstr, uint32_t len) {

	encode_generic_data_type(data, len, MAJOR_TYPE_2);
	printf("°°°°°°°°°°°°°°°°°°°°° byte string len %ld\n",len );
	/* add the string in the encoded data */
	uint32_t i;
	for(i=0; i<len; i++) {
		data->buf[data->ptr++] = bstr[i];
	}
}

/**
 * decode major type 2: byte string
 */
uint32_t decode_byte_string_length_only(cbor_data *data) {

	return decode_generic_data_type(data, MAJOR_TYPE_2);
}


uint32_t decode_byte_string(cbor_data *data, uint8_t *bstr) {

	uint32_t len = decode_generic_data_type(data, MAJOR_TYPE_2);

	uint32_t i;
	for(i=0; i<len; i++) {
		bstr[i] = data->buf[data->ptr++];
	}

	/* return length of the byte string */
	return len;
}



/************** major type 3: text string ******************/

/**
 * encode major type 3: text string
 */
void encode_text_string(cbor_data *data, char *tstr) {

	/* get the length of the string */
	uint32_t len = strlen(tstr);
	encode_generic_data_type(data, len, MAJOR_TYPE_3);

	/* add the string in the encoded data */
	unsigned long i;
	for(i=0; i<len; i++) {
		data->buf[data->ptr++] = (uint8_t) tstr[i];
	}
}

/**
 * decode major type 3: text string
 */
uint32_t decode_text_string(cbor_data *data, char *tstr) {
	uint32_t len = decode_generic_data_type(data, MAJOR_TYPE_3);
	uint32_t i;
	for(i=0; i<len; i++) {
		tstr[i] = (char)data->buf[data->ptr++] ;
	}
	tstr[len] = '\0';

	/* return length of the text string */
	return len;
}

/************** major type 4: array of data items ******************/

/**
 * encode major type 4: array of data items
 */
void encode_data_array(cbor_data *data, uint32_t len) {

	encode_generic_data_type(data, len, MAJOR_TYPE_4);
}

/**
 * decode major type 4: array of data items
 * @return length of the encoded data array
 */
uint32_t decode_data_array(cbor_data *data) {

	return decode_generic_data_type(data, MAJOR_TYPE_4);
}

/************** major type 5: map of pair of data items ******************/

/**
 * encode major type 5: map of pair of data items
 */
void encode_map_array(cbor_data *data, uint32_t len) {

	encode_generic_data_type(data, len, MAJOR_TYPE_5);
}

/**
 * decode major type 5: map of pair of data items
 * @return length of the encoded map array
 */
uint32_t decode_map_array(cbor_data *data) {

	return decode_generic_data_type(data, MAJOR_TYPE_5);
}

/************** major type 6: custom data type ******************/

/**
 * encode major type 6: custom data type
 */
void encode_major_type_six(cbor_data *data, uint8_t tag, uint8_t *dstr) {

	uint8_t i;

	encode_generic_data_type(data, tag, MAJOR_TYPE_6);

	if(tag == 1) {
		/* for tag 1 encode a bytes string of length 4*/
		for(i=0; i<4; i++) {
			data->buf[data->ptr++] = dstr[i];
		}
	} else {
		printf("%d is an unknown tag for major type 6\n", tag);
	}
}

/**
 * decode major type 6: custom data type
 */
void decode_major_type_six(cbor_data *data, uint8_t tag, uint8_t *dstr) {

	uint8_t t = (uint8_t) decode_generic_data_type(data, MAJOR_TYPE_6);
	uint8_t i;

	if(tag == t) {
		/* tag type 1 is 4 byte integer to represent NumericDate */
		for(i=0; i<4; i++) {
			dstr[i] = data->buf[data->ptr++];
		}
	} else {
		printf("Error: unknown tag %d for major type 6\n", tag);
	}
}

/************** major type 7: custom data type ******************/

/**
 * encode boolean: major type 7, value 21/20
 */
void encode_boolean(cbor_data *data, uint8_t boolean) {

	if(boolean == 1) {
		encode_generic_data_type(data, TRUE_TAG, MAJOR_TYPE_7);
	} else {
		encode_generic_data_type(data, FALSE_TAG, MAJOR_TYPE_7);
	}
}

/**
 * decode boolean: major type 7, value 21/20
 */
uint8_t decode_boolean(cbor_data *data) {

	uint8_t tag = (uint8_t) decode_generic_data_type(data, MAJOR_TYPE_7);

	if(tag == TRUE_TAG) {
		return 1;
	} else if(tag == FALSE_TAG) {
		return 0;
	} else {
		printf("Error: not a boolean type\n");
		return 0;
	}
}

/**
 * encode nil data type: major type 7, value 22
 */
void encode_nil(cbor_data *data) {

	encode_generic_data_type(data, NIL_TAG, MAJOR_TYPE_7);
}


/**
 * decode nil data type: major type 7, value 22
 */
uint8_t decode_nil(cbor_data *data) {

	uint8_t tag = decode_generic_data_type(data, MAJOR_TYPE_7);

	if(tag == NIL_TAG) {
		return 1;
	} else {
		return 0;
	}
}

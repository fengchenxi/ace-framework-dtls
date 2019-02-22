#ifndef CBOR_ENCODER_H_
#define CBOR_ENCODER_H_


#include <stdint.h>

#include <stdio.h>
#include <string.h>



enum major_type {
	MAJOR_TYPE_0 = 0x00,	/* unsigned integer */
	MAJOR_TYPE_1 = 0x20,	/* negative integer */
	MAJOR_TYPE_2 = 0x40,	/* byte string */
	MAJOR_TYPE_3 = 0x60,	/* text string */
	MAJOR_TYPE_4 = 0x80,	/* array of data items */
	MAJOR_TYPE_5 = 0xa0,	/* map of pair of data items */
	MAJOR_TYPE_6 = 0xc0,
	MAJOR_TYPE_7 = 0xe0
};

typedef struct cbor_data_struct {
	uint8_t *buf;
	uint32_t ptr;//Pointer record
} cbor_data;




void print_byte_string(uint8_t *bytes, uint16_t len);


void encode_following_bytes(cbor_data *data, uint32_t d, signed char num_bytes);
uint32_t decode_following_bytes(cbor_data *data, uint8_t num_bytes);


void encode_unsigned_int(cbor_data *data, uint32_t v);
void encode_negative_int(cbor_data *data, long v);
void encode_byte_string_length_only(cbor_data *data, uint32_t len);
void encode_byte_string(cbor_data *data, uint8_t *str, uint32_t len);
void encode_text_string(cbor_data *data, char *str);
void encode_data_array(cbor_data *data, uint32_t len);
void encode_map_array(cbor_data *data, uint32_t len);
void encode_major_type_six(cbor_data *data, uint8_t tag, uint8_t *dstr);
void encode_boolean(cbor_data *data, uint8_t boolean);
void encode_nil(cbor_data *data);


uint32_t decode_unsigned_int(cbor_data *data);
long  decode_negative_int(cbor_data *data);
uint32_t decode_byte_string_length_only(cbor_data *data);
uint32_t decode_byte_string(cbor_data *data, uint8_t *bstr);
uint32_t decode_text_string(cbor_data *data, char *tstr);
uint32_t decode_data_array(cbor_data *data);
uint32_t decode_map_array(cbor_data *data);
void decode_major_type_six(cbor_data *data, uint8_t tag, uint8_t *dstr);
uint8_t decode_boolean(cbor_data *data);
uint8_t decode_nil(cbor_data *data);

#endif  /* CBOR_ENCODER_H_ */

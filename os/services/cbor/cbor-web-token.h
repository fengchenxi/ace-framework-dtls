#ifndef CBOR_WEB_TOKEN_H_
#define CBOR_WEB_TOKEN_H_

#include "cbor-encoder.h"

enum cbor_encoded_claim_key{
	ISS=1,//Issuer -> string
	SUB=2,//Subject -> String
	AUD=3,//AUD -> String
    EXP=4,//Expiration time -> NumericDate
	NBF=5,//Issued at -> NumericDate
	IAT = 6,    //Issued at -> NumericDate 
	CTI = 7,     // CWT ID -> String

	// ACE RELATED FIELDS https://tools.ietf.org/pdf/draft-ietf-ace-oauth-authz-10.pdf
	// section 5.6.5 5.7.4
	CLIENT_ID     = 8,  // String (Majot Type 3)
	// CLIENT_SECRET = 9,
	// RESPONSE_TYPE = 10,
	// REDIRECT_URL  = 11,
	SCOPE  		  = 9, // String (Majot Type 3)
//	SCOPE,
//	GRANT_TYPE,
//	ACCESS_TOKEN,
//	TOKEN_TYPE,
//	USERNAME,
//	PASSWORD,
//	CNF,
//	PROFILE,
	// STATE  		  = 13,
	// CODE  		  = 14,
	// ERROR  		  = 15,
	// ERROR_DES  	  = 16,
	// ERROR_URI  	  = 17,
	GRANT_TYPE    = 10, // uint  (Majot Type 0)
	ACCESS_TOKEN  = 11, // String (Majot Type 3)
	TOKEN_TYPE    = 12, // String (Majot Type 3)
	// EXPIRES_IN    = 21,
	USERNAME  	  = 13, // String (Majot Type 3)
	PASSWORD  	  = 14, // String (Majot Type 3)
	// REFRESH_TOKEN = 24,
	CNF  		  = 15,  // Map (Majot Type 5)
	PROFILE  	  = 16,  // String (Majot Type 3)
	// token	      = 27  // text string
        // token_type_hint = 28  //text string
        //active=29   //unsigned integer
        //client_token //byte string
       //RS_CNF = 31  //map

	COSE_ENCRYPTED=17,
	CNF_KEY_ID=18,
	COSE_KEY=19,
	COSE_KEY_TYPE=20,
	COSE_KEY_ID=21,	
	PSK_KEY=22



	//IPSEC_STRUC,  contains security and network parameters of an SA pair
	//KMP,   indicate the key management protocol to be used to establish a SA pair
//	COSE_KEY_CRV,
//	COSE_KEY_X,
//	COSE_KEY_Y,

/*If C has previously received a PSK from the AS, then C must provide a key identifier 
of that PSK either directly in the kid field of 'cnf' parameter or in the 'kid' field of
the COSE key object of the acess token response
*/	
//	ALG

};

typedef struct cwt_struct
{
	uint8_t *claim_key;
	uint8_t **claim;
	int8_t claim_count;
	int8_t max_count;
} cbor_web_token;

typedef struct dtls_channel_struc
{
#if DTLS_PSK
  uint8_t id[32];
  uint8_t key[32];
#endif
#if DTLS_ECC
#endif	
}dtls_channel;

/*typedef struct access_token_struc {
	char mode[10];
	uint32_t life;
	char *ip_c;
	char *ip_rs;
	uint32_t spi_sa_c;
	uint32_t spi_sa_rs;
	uint32_t prot_type;
	uint32_t encr_alg;

    const char *seed;
  #if WITH_CONF_MANUAL_SA
     uint8_t psk[1];
  #else
    #if WITH_CONF_IPSEC_IKE
      #if WITH_CONF_IKE_CERT_AUTH == 0
      uint8_t psk[32];
      #else
      uint8_t psk[950];
      #endif
    #endif
  #endif

} access_token;
*/


void integer2bytestring(uint32_t data, uint8_t num_bytes, uint8_t *dstr);


void initiate_cbor_web_token(cbor_web_token *cbor_wtoken, int8_t num_claims);
void encode_cbor_web_token(cbor_data *data, cbor_web_token *cbor_wtoken);
void encode_struc_in_cnf(cbor_data *data, uint8_t cnf_key, uint8_t *method, uint32_t struct_len);
//void decode_cbor_web_token(cbor_data *data, cbor_web_token *cbor_wtoken)
void decode_cbor_web_token(cbor_data *data, uint8_t *claim, dtls_channel *new_dtls_channel);//, cbor_web_token *cbor_wtoken);

void encode_cwt_directly(cbor_data *data, uint8_t claim_key, uint8_t *claim);
//void decode_cwtbor_web_token(cbor_data *data, cbor_web_token *cbor_wtoken);



void encode_cnf(cbor_data *data, uint8_t cnf_key, uint8_t *method);
//void  decode_cnf(cbor_data *data, dtls_channel *new_dtls_channel);//, cbor_web_token *cbor_wtoken)

void encode_cose_key(cbor_data *data, uint8_t ck_key, char *method);
//void decode_cose_key(cbor_data *data, dtls_channel *new_dtls_channel);//, cbor_web_token *cbor_wtoken)

#endif  /* CBOR_WEB_TOKEN_H_ */


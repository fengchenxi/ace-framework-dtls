#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "coap-keystore-simple.h"
#include "coap-keystore.h"
#include "cbor-encoder.h"
#include "cbor-web-token.h"
#include "cose-encoder.h"
// #include "dtls_profile_utils.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP


#if WITH_DTLS

uint8_t psk_default_id[32];
 
uint8_t psk_default_key[32];

void process_psk_token_client(dtls_channel *new_dtls_channel){
 // uint8_t psk[32] = "2123456789abcdef0123456789abcdef";
#if DISABLE_PRINTF
  printf("\n\nProcessing token Client side PSK\n\n");
  printf("new_dtls_channel->id is %s\n",new_dtls_channel->id);
  printf("new_dtls_channel->key is %s\n",new_dtls_channel->key);
#endif
#ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
    #ifdef COAP_DTLS_PSK_DEFAULT_KEY
	//    void *memcpy(void *dest, const void *src, size_t n);
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_IDENTITY,sizeof(COAP_DTLS_PSK_DEFAULT_IDENTITY));
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_KEY,sizeof(COAP_DTLS_PSK_DEFAULT_KEY));
#endif
#endif
//  set_psk_id(new_dtls_channel->id);
//  set_psk_key(new_dtls_channel->key);
  // set_spd_rs_null();
};

void process_psk_token_rs(dtls_channel *new_dtls_channel){
 // uint8_t psk[32] = "2123456789abcdef0123456789abcdef";
#if DISABLE_PRINTF
  printf("\n\nProcessing token RS side PSK\n\n");
  printf("new_dtls_channel->id is %s\n",new_dtls_channel->id);
  printf("new_dtls_channel->id is %s\n",new_dtls_channel->key);
#endif
#ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
    #ifdef COAP_DTLS_PSK_DEFAULT_KEY
	//    void *memcpy(void *dest, const void *src, size_t n);
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_IDENTITY,sizeof(COAP_DTLS_PSK_DEFAULT_IDENTITY));
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_KEY,sizeof(COAP_DTLS_PSK_DEFAULT_KEY));
#endif
#endif																																																																																																																																																																																																																																																																																																								
//  set_psk_id(new_dtls_channel->id);
//  set_psk_key(new_dtls_channel->key);
//  set_spd_client_null();
};

/*
void process_cert_token_client(ipsec_sa *new_ipsec_sa){
  printf("\n\nProcessing token Client side Cert\n\n");
  static uint8_t cert_bytes[400];
  hex_string_to_array(new_ipsec_sa->psk, &cert_bytes);
  set_cert(&cert_bytes,strlen(new_ipsec_sa->psk)/2);
  // set_spd_rs_null();
};

void process_cert_token_rs(ipsec_sa *new_ipsec_sa){
  printf("\n\nProcessing  token RS side Cert\n\n");
  PRINTF("size of cert %d\n", strlen(new_ipsec_sa->psk));
  static uint8_t cert_bytes[400];
  hex_string_to_array(new_ipsec_sa->psk, &cert_bytes);
  //printf("------ %d -----", strlen(cert_bytes));
  set_spd_client_null();
  set_cert(&cert_bytes,strlen(new_ipsec_sa->psk)/2);
  PRINTF("\n\nProcessing  token RS side Cert... ...\n\n");
};
*/
#endif

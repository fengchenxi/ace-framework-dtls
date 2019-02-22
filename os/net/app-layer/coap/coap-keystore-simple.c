/*
 * Copyright (c) 2017, RISE SICS AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         A simple keystore with fixed credentials.
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

/**
 * \addtogroup coap-keystore
 * @{
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coap-endpoint.h"
#include "coap-keystore.h"





/* 
#if WITH_DTLS  



void set_psk_id(uint8_t *id){
#ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
  uint8_t psk_default_id[32]= COAP_DTLS_PSK_DEFAULT_IDENTITY;
#ifdef DISABLE_PRINTF  
	printf("COAP_DTLS_PSK_DEFAULT_IDENTITY %s\n",psk_default_id);
#endif
  #else
  uint8_t i=0,
  uint8_t psk_default_id = *id ;
  for(i=0;i<32;i++){
    psk_default_id[i]=id[i];
  }
#ifdef DISABLE_PRINTF 
  printf("psk_default_identity is %u\n",psk_default_id);
#endif
  #endif  
}


void set_psk_key(uint8_t *key){
  #ifdef COAP_DTLS_PSK_DEFAULT_KEY
  uint8_t psk_default_key[32]= COAP_DTLS_PSK_DEFAULT_KEY;
#ifdef DISABLE_PRINTF
  printf("COAP_DTLS_PSK_DEFAULT_KEY %s\n",psk_default_key);
#endif
  #else
  uint8_t i=0;
  uint8_t psk_default_key = *key;
  for(i=0;i<32;i++){
    psk_default_key[i]=key[i];  
  }
#ifdef DISABLE_PRINTF
  printf("psk_default_key is %u\n",psk_default_key);
#endif
  #endif
}
#endif
*/
/*
uint8_t set_psk_id(uint8_t *id){
const char *psk_default_id ="Client_identity";
//  uint8_t i=0;
  for(i=0;i<32;i++){
    psk_default_id[i] = id1[i];
    printf("%u",psk_default_id[i]);
  }
// strcpy(psk_default_key , "Client_identity");

//    psk_default_id=id1;
  #ifdef DISABLE_PRINTF
  printf("\n");
  printf("psk_default_identity is setting\n" );
  #endif
	return uint8_t(psk_default_id);
}

uint8_t set_psk_key(uint8_t *key){
const char *psk_default_key = "secretPSK";
//  uint8_t i=0;
  for(i=0;i<32;i++){
    psk_default_key[i] = key1[i];
    printf("%u",psk_default_key[i]);
  }
//  strcpy(psk_default_key , "secretPSK");
#ifdef DISABLE_PRINTF
  printf("\n");
  printf("psk_default_key is setting\n");
#endif
	return uint8_t(psk_default_key);

}

*/



#ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
#ifdef COAP_DTLS_PSK_DEFAULT_KEY
/*---------------------------------------------------------------------------*/



/*static int
get_default_psk_info_2(const coap_endpoint_t *address_info,
                     coap_keystore_psk_entry_t *info)
{
    #ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
    #ifdef COAP_DTLS_PSK_DEFAULT_KEY
	//    void *memcpy(void *dest, const void *src, size_t n);
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_IDENTITY,sizeof(COAP_DTLS_PSK_DEFAULT_IDENTITY));
    memcpy(psk_default_id,COAP_DTLS_PSK_DEFAULT_KEY,sizeof(COAP_DTLS_PSK_DEFAULT_KEY));
//  for(int i=0;i<32;i++){
//    psk_default_id[i] = COAP_DTLS_PSK_DEFAULT_IDENTITY[i];
//    psk_default_key[i]=COAP_DTLS_PSK_DEFAULT_KEY[i];
//  }
#if DISABLE_PRINTF
    printf("COAP_DTLS_PSK_DEFAULT_IDENTITY  set\n");
    printf("COAP_DTLS_PSK_DEFAULT_KEY  set\n");
#endif
   #endif
   #endif



  if(info != NULL) {
    if(info->identity == NULL || info->identity_len == 0) {
      // Identity requested 
      info->identity = psk_default_id;
      info->identity_len = strlen((const char *)psk_default_id);

      return 1;
    }

//    if(info == NULL){
//       coap_keystore_psk_entry_t info = {
//      .identity= psk_default_id,
//      .identity_len= strlen((const char *)psk_default_id),
//      .key= psk_default_key,
//      .key_len= strlen((const char *)psk_default_key)
//     };
//     return 1;
//   }

    if(info->identity_len != strlen((const char *)psk_default_id)||
       memcmp(info->identity, psk_default_id,
              info->identity_len) != 0) {
      //Identity not matching
  printf("The psk size is not match with other psk size\n" );
  printf("\n\n");
  printf("\nPRINT THE SET PSK IDENTITY\n" );
  for(int i=0;i<32;i++){
   printf("%u",psk_default_id[i]); 
  } 
  printf("\n\n");
  printf("\nPRINT THE SET PSK key\n" );
  for(int i=0;i<32;i++){
   printf("%u",psk_default_key[i]); 
  }
  printf("\n\n");
      return 0;
    }
    info->key = psk_default_key;
    info->key_len = strlen((const char *)psk_default_key);
    printf("the identity of the key is %s\n",info->key);
    printf("the length of the key is %d\n",info->key_len);
    return 1;
  }
  return 0;
}
*/
#if WITH_DTLS
static int
get_default_psk_info(const coap_endpoint_t *address_info,
                     coap_keystore_psk_entry_t *info)
{
  if(info != NULL) {
    if(info->identity == NULL || info->identity_len == 0) {
      /* Identity requested */
      info->identity = (uint8_t *)COAP_DTLS_PSK_DEFAULT_IDENTITY;
      info->identity_len = strlen(COAP_DTLS_PSK_DEFAULT_IDENTITY);
      return 1;
    }
    if(info->identity_len != strlen(COAP_DTLS_PSK_DEFAULT_IDENTITY) ||
       memcmp(info->identity, COAP_DTLS_PSK_DEFAULT_IDENTITY,
              info->identity_len) != 0) {
      /* Identity not matching */
      return 0;
    }
    info->key = (uint8_t *)COAP_DTLS_PSK_DEFAULT_KEY;
    info->key_len = strlen(COAP_DTLS_PSK_DEFAULT_KEY);
    return 1;
  }
  return 0;
}


static const coap_keystore_t simple_key_store = { 
	.coap_get_psk_info = get_default_psk_info
  };
	
/*---------------------------------------------------------------------------*/
#endif /* COAP_DTLS_PSK_DEFAULT_KEY */
#endif /* COAP_DTLS_PSK_DEFAULT_IDENTITY */

#endif /* WITH_DTLS */
/*---------------------------------------------------------------------------*/
void coap_keystore_simple_init(void)
{
#if WITH_DTLS
#ifdef COAP_DTLS_PSK_DEFAULT_KEY
#ifdef COAP_DTLS_PSK_DEFAULT_IDENTITY
//#ifdef psk_default_key

  coap_set_keystore(&simple_key_store);

//#endif /* COAP_DTLS_PSK_DEFAULT_KEY */
//#endif /* COAP_DTLS_PSK_DEFAULT_IDENTITY */

//#ifndef COAP_DTLS_PSK_DEFAULT_IDENTITY
//#ifndef COAP_DTLS_PSK_DEFAULT_KEY
//  coap_set_keystore(&simple_key_store);
#endif /* COAP_DTLS_PSK_DEFAULT_KEY */
#endif /* COAP_DTLS_PSK_DEFAULT_IDENTITY */
#endif /* WITH_DTLS */
}
/*---------------------------------------------------------------------------*/
/** @} */

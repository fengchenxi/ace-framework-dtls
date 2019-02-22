/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"
#include "coap.h"

#include <stdio.h> /* For printf() */
#include "uip-udp-packet.h"
#include "uip.h"
// #include "ipsec.h"
// #include "sad-conf.c"

#include "cbor-web-token.h"
// #include "ipsec.h"
// #include "ipsec-conf.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip.h"
#include "cose-encoder.h"

#include "ace-token.h"
#if WITH_DTLS
#include "dtls_profile_utils.h"
#endif
uint8_t flag_decode = 0;

#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_RPL


#if ACE_INFO
#include "sys/rtimer.h"
#include "sys/energest.h"
//#include "powertrace.h"
// rtimer_clock_t exec_time_ace = 0;
// rtimer_clock_t total_time_ace = 0;
// uint32_t cpu = 0;
// uint32_t transmit = 0;
#endif
static void res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

#if ACE_INFO
uint64_t transmit_time,transmit_time2;
uint64_t listen_time,listen_time2;
uint64_t lpm_time,lpm_time2;
uint64_t cpu_time,cpu_time2;
uint64_t deep_lpm_time,deep_lpm_time2;
uint64_t total_time,total_time2;
uint64_t radio_off,radio_off2;


#endif


RESOURCE(res_rs_authz_info,
         "title=\"Authz-Info Endpoint",
         NULL,
         res_post_handler,
         NULL,
         NULL);




// PROCESS ACCESS TOKEN GOT BY POST REQUEST
static void
res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
#if ACE_INFO
//  powertrace_sniff(POWERTRACE_ON);

   /* Update all energest times. */
  energest_init();
  energest_flush();
  
   cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) ;
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) ;
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM);
   transmit_time2= energest_type_time(ENERGEST_TYPE_TRANSMIT) ;
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) ;
   total_time2 = ENERGEST_GET_TOTAL_TIME();
   radio_off2 = ENERGEST_GET_TOTAL_TIME() ;
     printf("\n all the times\n");
  printf("\n....................................................\n");
   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF %4llu\n", 
                  cpu_time2,
                  lpm_time2,
                  deep_lpm_time2,
                  transmit_time2,
                  listen_time2,
                  total_time2,
                  radio_off2
                  );
#endif
  static dtls_channel new_dtls_channel;
  // process_direct_provisioning_token_rs(new_ipsec_sa);
  // uint8_t psk[950];
  // new_ipsec_sa.psk = &psk;

  printf("POST TOKEN RECEIVED\n");

  const uint8_t *payload = NULL;  
  int l = coap_get_payload(request, &payload);
    printf(">>>>>> payload len ---- %d\n",l);
   // cbor_data cb_data;
   // cb_data.buf =  payload;
   // cb_data.ptr = 0;


   if (flag_decode == 0){
    LOG_INFO("DECONDING and DECRYPTING CBOR PAYLOAD...");



    static uint8_t payload_bytes_cose[1200];
    cbor_data cb_data;
    cb_data.buf = (uint8_t *)payload;
    cb_data.ptr = 0;
    #if ACE_INFO

//  #if  DISABLE_PRINTF_INSIDE  
  printf("\n................  ACE STATS  .....................\n");
//  printf("ENERGEST: \n");
  printf("0.T_dec_rs start\t");
  printf("\n....................................................\n"); 
//  #endif 
//  powertrace_print("0.T_dec_c start\t");
	
   cpu_time = energest_type_time(ENERGEST_TYPE_CPU);
   lpm_time = energest_type_time(ENERGEST_TYPE_LPM);
   deep_lpm_time = energest_type_time(ENERGEST_TYPE_DEEP_LPM); 
   transmit_time = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   listen_time = energest_type_time(ENERGEST_TYPE_LISTEN);
   total_time = ENERGEST_GET_TOTAL_TIME();
   radio_off = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN); 


    #endif
    unwrap_cose_envelope(&cb_data, COSE_ENCRYPT0, payload_bytes_cose, l);

    #if ACE_INFO
   cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) - cpu_time;
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) - lpm_time;
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM) - deep_lpm_time;
   transmit_time2 = energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit_time;
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) - listen_time;
   total_time2 = ENERGEST_GET_TOTAL_TIME() - total_time;
   radio_off2 = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN) - radio_off;
//  #if  DISABLE_PRINTF_INSIDE
   //     cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) ;
   // lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) ;
   // deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM) ;
   // transmit_time2 = energest_type_time(ENERGEST_TYPE_TRANSMIT) ;
   // listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) ;
   // total_time2 = ENERGEST_GET_TOTAL_TIME() - total_time;
   // radio_off2 = ENERGEST_GET_TOTAL_TIME() ;
   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF%4llu\n", 
                  cpu_time2,
                  lpm_time2,
                  deep_lpm_time2,
                  transmit_time2,
                  listen_time2,
                  total_time2,
                  radio_off2
                  );
  printf("0.T_dec_rs stop\t");
  printf("\n....................................................\n");
//   #endif
  #endif
    l = cb_data.ptr;

  // cbor_data cb_data;
    cb_data.buf =  payload_bytes_cose;
    cb_data.ptr = 0;


   // cbor_data cb_data;
   // cb_data.buf =  payload;
   // cb_data.ptr = 0;
    static uint8_t claim[950];
    decode_cbor_web_token(&cb_data, claim, &new_dtls_channel);
    printf("@@@@@ len %d @@@@",sizeof(new_dtls_channel)/sizeof(uint8_t));
   flag_decode = 1;
   }else{
    LOG_INFO("CBOR ALREADY DECODED...");
   }
#if WITH_DTLS
    #if DTLS_PSK
      process_psk_token_rs(&new_dtls_channel);
//      #else
//       #if DTLS_ECC
//      process_cert_token_rs(&new_dtls_channel);
//      #endif
    #endif
#endif
  LOG_INFO("\nRESPONDING...\n");
  const char *len = NULL;
  char const *const message = "Token received\n";
  int length = strlen(message);
  if(coap_get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if(length < 0) {
      length = 0;
    }
    if(length > REST_MAX_CHUNK_SIZE) {
      length = REST_MAX_CHUNK_SIZE;
    }
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  } 
  coap_set_header_content_format(response, TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  coap_set_header_etag(response, (uint8_t *)&length, 1);
  coap_set_payload(response, buffer, length);

  LOG_INFO("\n--------------------------------------------\n");

#if ACE_INFO
   cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) - cpu_time;
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) - lpm_time;
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM) - deep_lpm_time;
   transmit_time2= energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit_time;
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) - listen_time;
   total_time2 = ENERGEST_GET_TOTAL_TIME() - total_time;
   radio_off2 = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN) - radio_off;

   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF %4llu\n", 
                  cpu_time2,
                  lpm_time2,
                  deep_lpm_time2,
                  transmit_time2,
                  listen_time2,
                  total_time2,
                  radio_off2
                  );

  printf("\n................  ACE STATS  .....................\n");
  printf("5.stop\t");
  printf("\n....................................................\n");



   cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) ;
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) ;
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM);
   transmit_time2= energest_type_time(ENERGEST_TYPE_TRANSMIT) ;
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) ;
   total_time2 = ENERGEST_GET_TOTAL_TIME();
   radio_off2 = ENERGEST_GET_TOTAL_TIME() ;
     printf("\n all the times\n");
  printf("\n....................................................\n");
   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF %4llu\n", 
                  cpu_time2,
                  lpm_time2,
                  deep_lpm_time2,
                  transmit_time2,
                  listen_time2,
                  total_time2,
                  radio_off2
                  );
   
#endif
}


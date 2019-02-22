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

#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"


#include <stdio.h> /* For printf() */
#include "uip-udp-packet.h"
#include "uip.h"
//#if WITH_IPSEC
//#include "sad.h"
//#endif

#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip.h"
#include "cose-encoder.h"

#include "coap-log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP
#include "sys/energest.h"


#if ACE_INFO
#include <stdio.h>
#include "sys/rtimer.h"
//#include "powertrace.h"
#endif
#include "ace-token.h"
static void res_get_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
#if ACE_INFO
uint64_t  transmit_time,transmit_time2;
uint64_t  listen_time,listen_time2;
uint64_t  lpm_time,lpm_time2;
uint64_t  cpu_time,cpu_time2;
uint64_t  deep_lpm_time,deep_lpm_time2;
uint64_t  total_time,total_time2;
uint64_t  radio_off,radio_off2;


//#endif
#endif

RESOURCE(res_as_token,
         "title=\"Token Endpoint\"",
         res_get_handler,
         NULL,
         NULL,
         NULL);


// PROCESS ACCESS TOKEN GOT BY POST REQUEST
//use local resource state that is accessed by res_get_handler()
static void
res_get_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
   /* Update all energest times. */

  energest_flush();
#if ACE_INFO
//  #if DISABLE_PRINTF_INSIDE
  printf("\n................  ACE STATS  .....................\n");
  printf("2.start\t");
  printf("\n....................................................\n");  
//  #endif
 printf("0.T_dec_c start\t");
   cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU);
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM);
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM); 
   transmit_time2 = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN);
   total_time2 = ENERGEST_GET_TOTAL_TIME();
   radio_off2 = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN); 

#endif

#if DISABLE_PRINTF   
  printf("ACCESS TOKEN REQUEST RECEIVED\n");
#endif
  const uint8_t *payload = NULL;
//coap_get_payload(void *packet, const uint8_t **payload)
  coap_get_payload(request, &payload);

  // coap_init_message(response, COAP_TYPE_CON, COAP_GET, 0);

  // const char *len = NULL;
  static uint8_t payload_bytes[1200];
	uint16_t payload_len;
    // uint8_t *payload_bytes;
    // uint8_t *buf2;
    // payload_bytes=malloc(1200*sizeof(uint8_t));
    // buf2=malloc(200*sizeof(uint8_t));

   cbor_data payload_cbor;
   payload_cbor.buf = payload_bytes;
   payload_cbor.ptr = 0;

     // uint16_t payload_len;

  
  uint8_t mode = 0;

#if WITH_DTLS
//  #if DTLS_PSK
      mode = 1; // PSK
//    #else
//    #if DTLS_RPK
//      mode = 2; // RPK
//    #endif
//   #endif
#endif
  #if DISABLE_PRINTF
  printf("ACCESS TOKEN REQUEST RECEIVED\n");
	// static uint8_t claim[950];
  #endif
  payload_len = generate_dummy_access_token(&payload_cbor, mode);

  static uint8_t data_bytes[2000];
  cbor_data cb_data;
  cb_data.buf = data_bytes;
  cb_data.ptr = 0;

  #if ACE_INFO

//  #if  DISABLE_PRINTF_INSIDE

  printf("\n................  ACE STATS  .....................\n");
//  printf("ENERGEST: \n");
 printf("0.T_enc_as start\t");
  printf("\n....................................................\n"); 

//  #endif 
 // powertrace_print("0.T_dec_c start\t");
   // cpu_time = energest_type_time(ENERGEST_TYPE_CPU);
   // lpm_time = energest_type_time(ENERGEST_TYPE_LPM);
   // deep_lpm_time = energest_type_time(ENERGEST_TYPE_DEEP_LPM); 
   // transmit_time = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   // listen_time = energest_type_time(ENERGEST_TYPE_LISTEN);
   // total_time = ENERGEST_GET_TOTAL_TIME();
   // radio_off = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN); 
 cpu_time = energest_type_time(ENERGEST_TYPE_CPU);
   lpm_time = energest_type_time(ENERGEST_TYPE_LPM);
   deep_lpm_time = energest_type_time(ENERGEST_TYPE_DEEP_LPM); 
   transmit_time = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   listen_time = energest_type_time(ENERGEST_TYPE_LISTEN);
   total_time = ENERGEST_GET_TOTAL_TIME();
   radio_off = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN); 
  #endif
//void wrapin_cose_envelope(cbor_data *data, enum cose_type ctype, uint8_t *payload_bytes, uint16_t payload_len);
//encode cose key
  wrapin_cose_envelope(&cb_data, COSE_ENCRYPT0, payload_bytes, payload_len);
  #if ACE_INFO
   cpu_time = energest_type_time(ENERGEST_TYPE_CPU) - cpu_time;
   lpm_time = energest_type_time(ENERGEST_TYPE_LPM) - lpm_time;
   deep_lpm_time = energest_type_time(ENERGEST_TYPE_DEEP_LPM) - deep_lpm_time;
   transmit_time = energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit_time;
   listen_time = energest_type_time(ENERGEST_TYPE_LISTEN) - listen_time;
   total_time = ENERGEST_GET_TOTAL_TIME() - total_time2;
   radio_off = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN) - radio_off;

// //#if DISABLE_PRINTF_INSIDE
   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF %4llu\n", 
                  cpu_time,
                  lpm_time,
                  deep_lpm_time,
                  transmit_time,
                  listen_time,
                  total_time,
                  radio_off
                  );
  printf("\n 0.T_enc_as stop \t");
  printf("\n 0.T_enc_as stop \t");
  printf("\n....................................................\n");   
//#endif
  #endif
  #if DISABLE_PRINTF
  printf("\n....................................................\n");
  LOG_INFO_("Len before encrypting %d\n", payload_len);
  LOG_INFO_("Len after encrypting %lu\n", cb_data.ptr);
  #endif
    memcpy(buffer, data_bytes, cb_data.ptr);
    coap_set_payload(response, buffer, cb_data.ptr);
    coap_set_header_content_format(response, APPLICATION_LINK_FORMAT);

#if ACE_INFO
    cpu_time2 = energest_type_time(ENERGEST_TYPE_CPU) - cpu_time2;
   lpm_time2 = energest_type_time(ENERGEST_TYPE_LPM) - lpm_time2;
   deep_lpm_time2 = energest_type_time(ENERGEST_TYPE_DEEP_LPM) - deep_lpm_time2;
   transmit_time2= energest_type_time(ENERGEST_TYPE_TRANSMIT) - transmit_time2;
   listen_time2 = energest_type_time(ENERGEST_TYPE_LISTEN) - listen_time2;
   total_time2 = ENERGEST_GET_TOTAL_TIME() - total_time2;
   radio_off2 = ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN) - radio_off2;
//#if DISABLE_PRINTF_INSIDE
   printf("CPU  %4llu   LPM   %4llu   DEEP LPM   %4llu   TRANSMIT TIME   %4llu    LISTEN_TIME   %4llu\n  TOTAL TIME %4llu  RADIO OFF %4llu\n", 
                  cpu_time2,
                  lpm_time2,
                  deep_lpm_time2,
                  transmit_time2,
                  listen_time2,
                  total_time2,
                  radio_off2
                  );
//  powertrace_print("2.stop\t");
 printf("2.stop\t");
  printf("\n....................................................\n");
//  #endif
#endif
  #if DISABLE_PRINTF
  printf("Sending ACCESS TOKEN RESPONSE %d\n",payload_len);
  #endif
}


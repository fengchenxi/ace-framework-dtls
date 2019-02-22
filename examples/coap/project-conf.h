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
 *      Erbium (Er) example project configuration.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

//#define NUMWORDS 8
//The Energest module is enabled by configuring ENERGEST_CONF_ON to 1
#define ENERGEST_CONF_ON 0 
// #define ENERGEST_CONF_CURRENT_TIME clock_time
// #define ENERGEST_CONF_TIME_T clock_time_t
// #define ENERGEST_CONF_SECOND CLOCK_SECOND


// #define ENERGEST_CONF_PLATFORM_ADDITIONS ENERGEST_TYPE_COMPONENT1,ENERGEST_TYPE_COMPONENT2
// #define ENERGEST_CONF_ADDITIONS ENERGEST_TYPE_COMPONENT3,ENERGEST_TYPE_COMPONENT4
//#define ENERGEST_TIME_T 1
//#define ENERGEST_SECOND 1
/* Enable client-side support for COAP observe */
#define COAP_OBSERVE_CLIENT            1
//COAP CONFIGURATION

/*
#define UIP_CONF_BUFFER_SIZE 1280
#define COAP_MAX_CHUNK_SIZE 256
#define DTLS_MAX_BUF 256
#define COAP_MAX_OPEN_TRANSACTIONS 4
#define COAP_MAX_OBSERVER 3
*/
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG
#define LOG_LEVEL_APP LOG_LEVEL_DBG
#define LPM_CONF_MAX_PM 1

//#define COAP_DTLS_PSK_DEFAULT_IDENTITY "Client_identity"
//#define COAP_DTLS_PSK_DEFAULT_KEY "secretPSK"


//#define  WITH_DTLS 0
//#define  DTLS_ECC 0
//#define  DTLS_PSK 0
#define  ACE_INFO 0
#define  DISABLE_PRINTF   0
#define  DISABLE_PRINTF_INSIDE  0
#define  DISABLE_PRINTF_CBOR   0
//#define DTLS_ECC 0
//#define DTLS_PSK 1

//#define ACE_INFO 0
#endif /* PROJECT_CONF_H_ */

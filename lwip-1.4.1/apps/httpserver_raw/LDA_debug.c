/*
 * Copyright (c) 2015 Lindem Data Acquisition AS. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * these files except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * Author:       Joakim Myrland
 * website:      www.LDA.as
 * email:        joakim.myrland@LDA.as
 * project:      https://github.com/Lindem-Data-Acquisition-AS/iot_lib/
 *
 */

#ifdef DEBUG

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "httpserver_raw/LDA_debug.h"
#include "driverlib/uartstdio.h"
#include "lwip/udp.h"

//#define putudec(x)	UARTprintf("%d ",x)


static void
send_udp( char * debug_message ) {

    struct udp_pcb *pcb;
    pcb = udp_new();
    /* Use udp_bind and udp_sendto for multiple remote targets */
    err_t err = udp_bind(pcb, IP_ADDR_ANY, pcb->local_port);

    struct pbuf *p;
    p = pbuf_alloc(PBUF_TRANSPORT, strlen(debug_message), PBUF_RAM);
    memcpy (p->payload, debug_message, strlen(debug_message));
    err = udp_sendto(pcb, p, IP_ADDR_BROADCAST, 555);
    (void)err; //remove compiler warning

    if (p != NULL) {
        pbuf_free(p); //De-allocate packet buffer
    }

    if (pcb != NULL) {
        udp_remove(pcb);
    }

}

static void
send_udp_bin( uint8_t * msg, size_t len ) {

    struct udp_pcb *pcb;
    pcb = udp_new();
    /* Use udp_bind and udp_sendto for multiple remote targets */
    err_t err = udp_bind(pcb, IP_ADDR_ANY, pcb->local_port);

    struct pbuf *p;
    p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    memcpy (p->payload, msg, len);
    err = udp_sendto(pcb, p, IP_ADDR_BROADCAST, 555);
    (void)err; //remove compiler warning

    if (p != NULL) {
        pbuf_free(p); //De-allocate packet buffer
    }

    if (pcb != NULL) {
        udp_remove(pcb);
    }

}

void
send_debug_assert(char *pcFilename, uint32_t ui32Line) {

//#warning "putudec not defined"
    return;

    static char buf[64];

    strcpy( buf, "File: " );
    strncpy( buf + strlen(buf), pcFilename, 64 - 18 );
    strcpy( buf + strlen(buf), " Line: " );
    //putudec( buf + strlen(buf), ui32Line );

    if( strlen(buf) < 63 ) {
        buf[strlen(buf) + 1] = 0;
    } else {
        buf[63] = 0;
    }

    send_debug_message( buf, DEBUG_MESSAGE_ASSERT );

}

void
send_debug_message( char * debug_message, uint8_t debug_output_type ) {

    switch (debug_output_type) {

        case DEBUG_MESSAGE_DISPLAY:
            send_udp("send_debug_message: DISPLAY not implemented");
            break;

        case DEBUG_MESSAGE_LWIP:
            send_udp(debug_message);
            break;

        case DEBUG_MESSAGE_UART:
            /* not implemented */
            send_udp("send_debug_message: UART not implemented");
            break;

        default:
            send_udp("send_debug_message: TYPE error");
            break;

    }

}

void
send_debug_packet( uint8_t * debug_packet, size_t packet_length, uint8_t debug_output_type ) {

    switch (debug_output_type) {

        case DEBUG_MESSAGE_DISPLAY:
        send_udp("send_debug_message: DISPLAY not implemented");
        break;

        case DEBUG_MESSAGE_LWIP:
        send_udp_bin(debug_packet, packet_length);
        break;

        case DEBUG_MESSAGE_UART:
        /* not implemented */
        send_udp("send_debug_message: UART not implemented");
        break;

        default:
        send_udp("send_debug_message: TYPE error");
        break;

    }
}

#endif

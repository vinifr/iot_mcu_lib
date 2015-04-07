/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author:       Joakim Myrland
 * website:      www.LDA.as
 * email:        joakim.myrland@LDA.as
 * project:      https://github.com/Lindem-Data-Acquisition-AS/iot_lib/
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "httpserver_raw/fs.h"
#include "httpserver_raw/httpd.h"
#include "httpserver_raw/LDA_debug.h"
#include "jsmn.h"

#include "timers.h"
#include "inc/tm4c129xnczad.h"

extern volatile char uuid_lock[36];
extern TimerHandle_t timeout_timer;

// List of accepted URI for POST requests
static uint8_t http_post_uri_file_index = 0;
static uint32_t http_post_content_len = 0;
#define HTTP_POST_URI_NUM	1
const char *a[HTTP_POST_URI_NUM] = {
    "/relays.ajax"
};

static err_t
http_json_parse(char * json, uint32_t length) {

    jsmn_parser js_p;
    jsmntok_t tokens[21];
    jsmn_init(&js_p);
    jsmnerr_t json_parse_result = jsmn_parse( &js_p, json, length, tokens, sizeof(tokens)/sizeof(jsmntok_t) );

    /* Check if JSON is parsed correctly. json_parse_result = number of tokens. Negative if error */
    if (json_parse_result != 21) {

        switch(json_parse_result) {

            case JSMN_ERROR_NOMEM:
                send_debug_message( "Not enough tokens were provided" , DEBUG_MESSAGE_DEFAULT );
                break;

            case JSMN_ERROR_INVAL:
                send_debug_message( "Invalid character inside JSON string" , DEBUG_MESSAGE_DEFAULT );
                break;

            case JSMN_ERROR_PART:
                send_debug_message( "The string is not a full JSON packet, more bytes expected" , DEBUG_MESSAGE_DEFAULT );
                break;

            default:
                send_debug_message( "Invalid amount of tokens in JSON!" , DEBUG_MESSAGE_DEFAULT );
                break;

        }

        return ERR_ARG;
    }

    /* Check if we have a valid JSON message */
    if ( tokens[0].type != JSMN_OBJECT || tokens[0].size != 4 ) {
        send_debug_message( "tokens[0] is not an object!" , DEBUG_MESSAGE_DEFAULT );
        return ERR_ARG;
    } else if ( tokens[1].type != JSMN_STRING  || strncmp(&json[ tokens[1].start ], "uuid", 4) != 0) {
        send_debug_message( "tokens[1] is not a string!" , DEBUG_MESSAGE_DEFAULT );
        return ERR_ARG;
    } else if ( tokens[2].type != JSMN_STRING ) {
        send_debug_message( "tokens[2] is not a string!" , DEBUG_MESSAGE_DEFAULT );
        return ERR_ARG;
    } else if ( tokens[3].type != JSMN_STRING || strncmp(&json[ tokens[3].start ], "relays", 6) != 0) {
        send_debug_message( "tokens[3] is not a string!" , DEBUG_MESSAGE_DEFAULT );
        return ERR_ARG;
    } else if ( tokens[4].type != JSMN_ARRAY || tokens[4].size != 16 ) {
        send_debug_message( "tokens[4] is not an array!" , DEBUG_MESSAGE_DEFAULT );
        return ERR_ARG;
    }


    /* We have no lock; so we set it */
    if (uuid_lock[0] == 0) {
        memcpy((char *)uuid_lock, &json[ tokens[2].start ], sizeof(uuid_lock));

    /* We have a lock; so we check it */
    } else if (strncmp(&json[ tokens[2].start ], (char *)uuid_lock, sizeof(uuid_lock)) != 0) {
        return ERR_ARG;
    }

    static char str[17];
    uint16_t relay_output = 0;

    /* We have received the new relay configuration, so we can reset the
     * timeout timer */
    xTimerReset( timeout_timer, 10 );

    for ( uint8_t tok_len = 0; tok_len < tokens[4].size; tok_len++ ) {

        if ( tokens[tok_len+5].type == JSMN_PRIMITIVE ) {
            // if json primitive is '1', set the corresponding bit to 1, else set bit to 0
            relay_output |= ( json[ tokens[tok_len+5].start ] == '1' ) ? (1 << tok_len) : 0;
            str[tok_len]  =   json[ tokens[tok_len+5].start ];
        }

    }

    GPIO_PORTD_AHB_DATA_R = (uint32_t) ~(relay_output & 0xff);
    GPIO_PORTM_DATA_R = (uint32_t) ~((relay_output >> 8) & 0xff);

    str[16] = 0;
    send_debug_message( str , DEBUG_MESSAGE_DEFAULT );

    return ERR_OK;
}


/** Called when a POST request has been received. The application can decide
 * whether to accept it or not.
 *
 * @param connection Unique connection identifier, valid until httpd_post_end
 *        is called.
 * @param uri The HTTP header URI receiving the POST request.
 * @param http_request The raw HTTP request (the first packet, normally).
 * @param http_request_len Size of 'http_request'.
 * @param content_len Content-Length from HTTP header.
 * @param response_uri Filename of response file, to be filled when denying the
 *        request
 * @param response_uri_len Size of the 'response_uri' buffer.
 * @param post_auto_wnd Set this to 0 to let the callback code handle window
 *        updates by calling 'httpd_post_data_recved' (to throttle rx speed)
 *        default is 1 (httpd handles window updates automatically)
 * @return ERR_OK: Accept the POST request, data may be passed in
 *         another err_t: Deny the POST request, send back 'bad request'.
 */
err_t
httpd_post_begin(void *connection,
                 const char *uri,
                 const char *http_request,
                 u16_t http_request_len,
                 int content_len,
                 char *response_uri,
                 u16_t response_uri_len,
                 u8_t *post_auto_wnd) {

    for (uint8_t i=0; i<HTTP_POST_URI_NUM; i++) {

        if (strcmp(uri, a[i]) == 0) {

            http_post_uri_file_index = i;
            http_post_content_len = content_len;
            return ERR_OK;

        }

    }

    //returns /404.html when response_uri is empty
    return ERR_VAL;
}

/** Called for each pbuf of data that has been received for a POST.
 * ATTENTION: The application is responsible for freeing the pbufs passed in!
 *
 * @param connection Unique connection identifier.
 * @param p Received data.
 * @return ERR_OK: Data accepted.
 *         another err_t: Data denied, http_post_get_response_uri will be called.
 */
err_t
httpd_post_receive_data(void *connection, struct pbuf *p) {

    char *data;
    err_t ret_val = ERR_ARG;

    struct http_state *hs = (struct http_state*)connection;
    if (hs != NULL && p != NULL) {
        data = p->payload;
        ret_val = http_json_parse(data, http_post_content_len);
    }

    if (p != NULL) {
        pbuf_free(p);
    }

    return ret_val;
}

/** Called when all data is received or when the connection is closed.
 * The application must return the filename/URI of a file to send in response
 * to this POST request. If the response_uri buffer is untouched, a 404
 * response is returned.
 *
 * @param connection Unique connection identifier.
 * @param response_uri Filename of response file on success
 * @param response_uri_len Size of the 'response_uri' buffer.
 */
void
httpd_post_finished(void *connection,
                    char *response_uri,
                    u16_t response_uri_len) {

    struct http_state *hs = (struct http_state*)connection;
    if (hs != NULL) {
        strncpy(response_uri, a[http_post_uri_file_index], response_uri_len);
    }

}

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

#define DEBUG_MESSAGE_DISPLAY   0
#define DEBUG_MESSAGE_LWIP      1
#define DEBUG_MESSAGE_UART      2

#define DEBUG_MESSAGE_DEFAULT   DEBUG_MESSAGE_LWIP
#define DEBUG_MESSAGE_ASSERT    DEBUG_MESSAGE_LWIP

#include <stdint.h>

void send_debug_assert( char *pcFilename, uint32_t ui32Line );
void send_debug_message( char * debug_message, uint8_t debug_output_type );
void send_debug_packet( uint8_t * debug_packet, size_t packet_length, uint8_t debug_output_type );

#else

/* if DEBUG is not defined in preprocessor, remove functions from code with empty defines */
#define send_debug_assert(x, y)
#define send_debug_message(x, y)
#define send_debug_packet(x, y, z)

#endif

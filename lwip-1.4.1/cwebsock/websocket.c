/*
 * Copyright (c) 2014 Putilov Andrey
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "websocket.h"
#include "aw-base64.h"
#include "aw-sha1.h"

#include "driverlib/uartstdio.h"
#include "lwip/tcp.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/err.h"
#include "lwipopts.h"

#define MAXLN		512
#define ISSPACE		" \t\n\r\f\v"


// List of protocols supported
char *subprotocols[] = {
    "chat",
    "superchat",
    "echo-protocol"
};

static char rn[] PROGMEM = "\r\n";

static char * _getbase __P((char *, int *));
#ifdef HAVE_QUAD
static int _atob __P((unsigned long long *, char *p, int));
#else
static int _atob __P((unsigned long  *, char *, int));
#endif

static char *
_getbase(char *p, int *basep)
{
	if (p[0] == '0') {
		switch (p[1]) {
		case 'x':
			*basep = 16;
			break;
		case 't': case 'n':
			*basep = 10;
			break;
		case 'o':
			*basep = 8;
			break;
		default:
			*basep = 10;
			return (p);
		}
		return (p + 2);
	}
	*basep = 10;
	return (p);
}


/*
 *  _atob(vp,p,base)
 */
static int
#ifdef HAVE_QUAD
_atob (u_quad_t *vp, char *p, int base)
{
	u_quad_t value, v1, v2;
#else
_atob (unsigned long *vp, char *p, int base)
{
	u_long value, v1, v2;
#endif
	char *q, tmp[20];
	int digit;

	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		base = 16;
		p += 2;
	}

	if (base == 16 && (q = strchr (p, '.')) != 0) {
		if (q - p > sizeof(tmp) - 1)
			return (0);

		strncpy (tmp, p, q - p);
		tmp[q - p] = '\0';
		if (!_atob (&v1, tmp, 16))
			return (0);

		q++;
		if (strchr (q, '.'))
			return (0);

		if (!_atob (&v2, q, 16))
			return (0);
		*vp = (v1 << 16) + v2;
		return (1);
	}

	value = *vp = 0;
	for (; *p; p++) {
		if (*p >= '0' && *p <= '9')
			digit = *p - '0';
		else if (*p >= 'a' && *p <= 'f')
			digit = *p - 'a' + 10;
		else if (*p >= 'A' && *p <= 'F')
			digit = *p - 'A' + 10;
		else
			return (0);

		if (digit >= base)
			return (0);
		value *= base;
		value += digit;
	}
	*vp = value;
	return (1);
}

/*
 *  atob(vp,p,base) 
 *      converts p to binary result in vp, rtn 1 on success
 */
int
atob(uint32_t *vp, char *p, int base)
{
#ifdef HAVE_QUAD
	u_quad_t v;
#else
	u_long  v;
#endif

	if (base == 0)
		p = _getbase (p, &base);
	if (_atob (&v, p, base)) {
		*vp = v;
		return (1);
	}
	return (0);
}

/*
 *  vsscanf(buf,fmt,ap)
 */
static int Wvsscanf(const char *buf, const char *s, va_list ap)
{
    uint32_t       count, noassign, width, base=0, lflag;
    const char     *tc;
    char           *t, tmp[MAXLN];

    count = noassign = width = lflag = 0;
    while (*s && *buf) {
	while (isspace (*s))
	    s++;
	if (*s == '%') {
	    s++;
	    for (; *s; s++) {
		if (strchr ("dibouxcsefg%", *s))
		    break;
		if (*s == '*')
		    noassign = 1;
		else if (*s == 'l' || *s == 'L')
		    lflag = 1;
		else if (*s >= '1' && *s <= '9') {
		    for (tc = s; isdigit (*s); s++);
		    strncpy (tmp, tc, s - tc);
		    tmp[s - tc] = '\0';
		    atob (&width, tmp, 10);
		    s--;
		}
	    }
	    if (*s == 's') {
		while (isspace (*buf))
		    buf++;
		if (!width)
		    width = strcspn (buf, ISSPACE);
		if (!noassign) {
		    strncpy (t = va_arg (ap, char *), buf, width);
		    t[width] = '\0';
		}
		buf += width;
	    } else if (*s == 'c') {
		if (!width)
		    width = 1;
		if (!noassign) {
		    strncpy (t = va_arg (ap, char *), buf, width);
		    t[width] = '\0';
		}
		buf += width;
	    } else if (strchr ("dobxu", *s)) {
		while (isspace (*buf))
		    buf++;
		if (*s == 'd' || *s == 'u')
		    base = 10;
		else if (*s == 'x')
		    base = 16;
		else if (*s == 'o')
		    base = 8;
		else if (*s == 'b')
		    base = 2;
		if (!width) {
		    if (isspace (*(s + 1)) || *(s + 1) == 0)
			width = strcspn (buf, ISSPACE);
		    else
			width = strchr (buf, *(s + 1)) - buf;
		}
		strncpy (tmp, buf, width);
		tmp[width] = '\0';
		buf += width;
		if (!noassign)
		    atob (va_arg (ap, uint32_t *), tmp, base);
	    }
	    if (!noassign)
		count++;
	    width = noassign = lflag = 0;
	    s++;
	} else {
	    while (isspace (*buf))
		buf++;
	    if (*s != *buf)
		break;
	    else
		s++, buf++;
	}
    }
    return (count);
}

/*
 *  sscanf(buf,fmt,va_alist)
 */
int Wsscanf (const char *buf, const char *fmt, ...)
{
    int             count;
    va_list ap;
    
    va_start (ap, fmt);
    count = Wvsscanf (buf, fmt, ap);
    va_end (ap);
    return (count);
}

int findSubprotocol(char *s, int *id)
{
    int len = sizeof(subprotocols)/sizeof(subprotocols[0]);
    int i;

    for(i = 0; i < len; ++i)
    {
	if(!strcmp(subprotocols[i], s))
	{
	    *id = i;
	    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("Subprotocol supported %d\n",i));
	    return 0;
	}
    }
    return -1;
}
void nullHandshake(struct handshake *hs)
{
    hs->host = NULL;
    hs->origin = NULL;
    hs->resource = NULL;
    hs->key = NULL;
    hs->frameType = WS_EMPTY_FRAME;
}

void freeHandshake(struct handshake *hs)
{
    if (hs->host) {
        free(hs->host);
    }
    if (hs->origin) {
        free(hs->origin);
    }
    if (hs->resource) {
        mem_free(hs->resource);
    }
    if (hs->key) {
        free(hs->key);
    }
    if (hs->protocols) {
        free(hs->protocols);
    }

    nullHandshake(hs);
}

static char* getUptoLinefeed(const char *startFrom)
{
    char *writeTo = NULL;
    uint8_t newLength = strstr_P(startFrom, rn) - startFrom;
    //assert(newLength);
    writeTo = (char *)malloc(newLength+1); //+1 for '\x00'
    //assert(writeTo);
    memcpy(writeTo, startFrom, newLength);
    writeTo[ newLength ] = 0;

    return writeTo;
}

enum wsFrameType wsParseHandshake(const uint8_t *inputFrame, size_t inputLength,
                                  struct handshake *hs, int *err_code)
{
    const char *inputPtr = (const char *)inputFrame;
    const char *endPtr = (const char *)inputFrame + inputLength;
    *err_code = 0;

    //UARTprintf(inputFrame);

    if (!strstr((const char *)inputFrame, "\r\n\r\n")) {
	*err_code = 1;
        return WS_INCOMPLETE_FRAME;
    }
	
    if (memcmp_P(inputFrame, PSTR("GET "), 4) != 0) {
	*err_code = 2;
        return WS_ERROR_FRAME;
    }
    
    // measure resource size
    char *first = strchr((const char *)inputFrame, ' ');
    if (!first) {
	*err_code = 3;
        return WS_ERROR_FRAME;
    }
    first++;
    char *second = strchr(first, ' ');
    if (!second) {
	*err_code = 4;
        return WS_ERROR_FRAME;
    }

    if (hs->resource) {
        mem_free(hs->resource);
        hs->resource = NULL;
    }
    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("\nHandshake: Inicial tests OK\n"));

    hs->resource = (char *)mem_malloc(second - first + 1); // +1 is for \x00 symbol
    //assert(hs->resource);

    if (Wsscanf(inputPtr, PSTR("GET %s HTTP/1.1\r\n"), hs->resource) != 1)
    {
		LWIP_DEBUGF(WEBSOCKD_DEBUG, ("Error in Wsscanf\n"));
        return WS_ERROR_FRAME;
    }

    inputPtr = strstr_P(inputPtr, rn) + 2;

    /*
        parse next lines
     */
    #define prepare(x) do {if (x) { mem_free(x); x = NULL; }} while(0)
    #define strtolower(x) do { int i; for (i = 0; x[i]; i++) x[i] = tolower(x[i]); } while(0)
    uint8_t connectionFlag = FALSE;
    uint8_t upgradeFlag = FALSE;
    uint8_t subprotocolFlag = FALSE, subprotocolError = FALSE;
    uint8_t versionMismatch = FALSE;
    while (inputPtr < endPtr && inputPtr[0] != '\r' && inputPtr[1] != '\n') {
        if (memcmp_P(inputPtr, hostField, strlen_P(hostField)) == 0) {
            inputPtr += strlen_P(hostField);
            prepare(hs->host);
            hs->host = getUptoLinefeed(inputPtr);
        } else
        if (memcmp_P(inputPtr, originField, strlen_P(originField)) == 0) {
            inputPtr += strlen_P(originField);
            prepare(hs->origin);
            hs->origin = getUptoLinefeed(inputPtr);
        } else
        if (memcmp_P(inputPtr, protocolField, strlen_P(protocolField)) == 0) {
            inputPtr += strlen_P(protocolField);
			hs->protocols = getUptoLinefeed(inputPtr);
            subprotocolFlag = TRUE;
        } else
        if (memcmp_P(inputPtr, keyField, strlen_P(keyField)) == 0) {
            inputPtr += strlen_P(keyField);
            prepare(hs->key);
            hs->key = getUptoLinefeed(inputPtr);
        } else
        if (memcmp_P(inputPtr, versionField, strlen_P(versionField)) == 0) {
            inputPtr += strlen_P(versionField);
            char *versionString = NULL;
            versionString = getUptoLinefeed(inputPtr);
            if (memcmp_P(versionString, version, strlen_P(version)) != 0)
                versionMismatch = TRUE;
            free(versionString);//mem_free(versionString); PROBLEMA??????????
        } else
        if (memcmp_P(inputPtr, connectionField, strlen_P(connectionField)) == 0) {
            inputPtr += strlen_P(connectionField);
            char *connectionValue = NULL;
            connectionValue = getUptoLinefeed(inputPtr);
            strtolower(connectionValue);
            //assert(connectionValue);
            if (strstr_P(connectionValue, upgrade) != NULL)
                connectionFlag = TRUE;
            free(connectionValue); //mem_free(connectionValue); PROBLEMA??????????
        } else
        if (memcmp_P(inputPtr, upgradeField, strlen_P(upgradeField)) == 0) {
            inputPtr += strlen_P(upgradeField);
            char *compare = NULL;
            compare = getUptoLinefeed(inputPtr);
            strtolower(compare);
            //assert(compare);
            if (memcmp_P(compare, websocket, strlen_P(websocket)) == 0)
                upgradeFlag = TRUE;
            free(compare); //mem_free(compare); PROBLEMA??????????
        };

        inputPtr = strstr_P(inputPtr, rn) + 2;
    }

   if (subprotocolFlag)
       subprotocolError = findSubprotocol(hs->protocols, &hs->id);

    // we have read all data, so check them
    if (!hs->host || !hs->key || !connectionFlag || !upgradeFlag || subprotocolError
        || versionMismatch)
    {
	LWIP_DEBUGF(WEBSOCKD_DEBUG,("Error in Open frame\n"));
	if (subprotocolError)
	    LWIP_DEBUGF(WEBSOCKD_DEBUG,("Sub-protocol not supported\n"));
        hs->frameType = WS_ERROR_FRAME;
    } else {
        hs->frameType = WS_OPENING_FRAME;
    }
    //UARTprintf("\n###");
    return hs->frameType;
}

void wsGetHandshakeAnswer( struct handshake *hs, uint8_t *outFrame,
                          size_t *outLength)
{
    //assert(outFrame && *outLength);
    //assert(hs->frameType == WS_OPENING_FRAME);
    //assert(hs && hs->key);

    char *responseKey = NULL;

    uint8_t length = strlen(hs->key)+strlen_P(secret);
    responseKey = malloc(length);
    memcpy(responseKey, hs->key, strlen(hs->key));
    memcpy_P(&(responseKey[strlen(hs->key)]), secret, strlen_P(secret));
    unsigned char shaHash[20];
    memset(shaHash, 0, sizeof(shaHash));
    sha1(shaHash, responseKey, length);
    size_t base64Length = base64(responseKey, length, shaHash, 20);
    responseKey[base64Length-1] = '=';
    responseKey[base64Length] = '\0';    //

    int written = 0; // "HTTP/1.1 101 Switching Protocols\r\n"
    strcat((char *)outFrame,"HTTP/1.1 101 Web Socket Protocol Handshake\r\n");
    strcat((char *)outFrame,upgradeField);
    strcat((char *)outFrame,websocket);
    strcat((char *)outFrame,"\r\n");
    strcat((char *)outFrame,connectionField);
    strcat((char *)outFrame,upgrade2);
    strcat((char *)outFrame,"\r\n");        
    strcat((char *)outFrame,"Sec-WebSocket-Accept: ");
    strcat((char *)outFrame,responseKey);
    if (hs->protocols) {
	strcat((char *)outFrame,"\r\n");
	strcat((char *)outFrame,"Sec-WebSocket-Protocol: ");
	strcat((char *)outFrame, subprotocols[hs->id]);
    }
    strcat((char *)outFrame,"\r\n\r\n\0");
    written = strlen((char *)outFrame);
	
    free(responseKey);
    hs->protocols = NULL;
    // if assert fail, that means, that we corrupt memory
    //assert(written <= *outLength);
    *outLength = written;
}

int wsMakeFrame(const uint8_t *data, size_t dataLength,
                 uint8_t *outFrame, size_t *outLength, enum wsFrameType frameType)
{
    //assert(outFrame && *outLength);
    //assert(frameType < 0x10);
    //if (dataLength > 0)
        //assert(data);

    outFrame[0] = 0x80 | frameType;

    if (dataLength <= 125) {
        outFrame[1] = dataLength;
        *outLength = 2;
    } else if (dataLength <= 0xFFFF) {
        outFrame[1] = 126;
        uint16_t payloadLength16b = htons(dataLength);
        memcpy(&outFrame[2], &payloadLength16b, 2);
        *outLength = 4;
    } else {
        //assert(dataLength <= 0xFFFF);
        return (ERR_MEM);
    }
    memcpy(&outFrame[*outLength], data, dataLength);
    *outLength+= dataLength;
    
    return 0;
}

static size_t getPayloadLength(const uint8_t *inputFrame, size_t inputLength,
                               uint8_t *payloadFieldExtraBytes, enum wsFrameType *frameType) 
{
    size_t payloadLength = inputFrame[1] & 0x7F;
    *payloadFieldExtraBytes = 0;
    if ((payloadLength == 0x7E && inputLength < 4) || (payloadLength == 0x7F && inputLength < 10)) {
        *frameType = WS_INCOMPLETE_FRAME;
        return 0;
    }
    if (payloadLength == 0x7F && (inputFrame[3] & 0x80) != 0x0) {
        *frameType = WS_ERROR_FRAME;
        return 0;
    }

    if (payloadLength == 0x7E) {
        uint16_t payloadLength16b = 0;
        *payloadFieldExtraBytes = 2;
        memcpy(&payloadLength16b, &inputFrame[2], *payloadFieldExtraBytes);
        payloadLength = ntohs(payloadLength16b);
    } else if (payloadLength == 0x7F) {
        *frameType = WS_ERROR_FRAME;
        return 0;        
    }

    return payloadLength;
}

enum wsFrameType wsParseInputFrame(uint8_t *inputFrame, size_t inputLength,
                                   uint8_t **dataPtr, size_t *dataLength, int *err_code)
{
    //assert(inputFrame && inputLength);
    
    *err_code = 0;

    UARTprintf("\nwsParseInputFrame");

    if (inputLength < 2) {
	*err_code = 1;
        return WS_INCOMPLETE_FRAME;
    }
	
    if ((inputFrame[0] & 0x70) != 0x0) { // checks extensions off
	*err_code = 2;
        return WS_ERROR_FRAME;
    }
    if ((inputFrame[0] & 0x80) != 0x80) { // we haven't continuation frames support
	*err_code = 3;
        return WS_ERROR_FRAME; // so, fin flag must be set
    }
    if ((inputFrame[1] & 0x80) != 0x80) { // checks masking bit
	*err_code = 4;
        return WS_ERROR_FRAME;
    }

    uint8_t opcode = inputFrame[0] & 0x0F;
    if (opcode == WS_TEXT_FRAME ||
            opcode == WS_BINARY_FRAME ||
            opcode == WS_CLOSING_FRAME ||
            opcode == WS_PING_FRAME ||
            opcode == WS_PONG_FRAME
    ){
        enum wsFrameType frameType = opcode;

        uint8_t payloadFieldExtraBytes = 0;
        size_t payloadLength = getPayloadLength(inputFrame, inputLength,
                                                &payloadFieldExtraBytes, &frameType);
        if (payloadLength > 0) {
            if (payloadLength + 6 + payloadFieldExtraBytes > inputLength) // 4-maskingKey, 2-header
                return WS_INCOMPLETE_FRAME;
            uint8_t *maskingKey = &inputFrame[2 + payloadFieldExtraBytes];

            //assert(payloadLength == inputLength - 6 - payloadFieldExtraBytes);

            *dataPtr = &inputFrame[2 + payloadFieldExtraBytes + 4];
            *dataLength = payloadLength;
		
            size_t i;
            for (i = 0; i < *dataLength; i++) {
                (*dataPtr)[i] = (*dataPtr)[i] ^ maskingKey[i%4];
            }
        }
        return frameType;
    }

    return WS_ERROR_FRAME;
}


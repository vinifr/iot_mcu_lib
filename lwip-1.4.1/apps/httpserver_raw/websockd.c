
#include <string.h>
#include <stdlib.h>
#include "websockd.h"
#include "websocket.h"

#include "lwipopts.h"
#include "timers.h"
#include "driverlib/uartstdio.h"

#include "inc/tm4c129xnczad.h"


#define WEBSOCKD_SERVER_PORT 80
#define WEBSOCKD_TCP_PRIO                      TCP_PRIO_MIN

#define WEBSOCK_ALLOC_STATE() (struct websock_state *)mem_malloc(sizeof(struct websock_state))

#define NUM_FILE_HDR_STRINGS 3

#define BUF_LEN 512//0xFFFF
#define PACKET_DUMP

#define initNewFrame frameType = WS_INCOMPLETE_FRAME;

static err_t websock_close_conn(struct tcp_pcb *pcb, struct websock_state *hs,uint8_t abort_conn);
static err_t websock_poll(void *arg, struct tcp_pcb *pcb);
static int libwebsock_send_tcp(uint8_t *frame, u32_t size);
static err_t websock_parse_request(struct pbuf **inp, struct websock_state *whs, struct tcp_pcb *pcb);

volatile char ws_uuid_lock[36] = {0};
TimerHandle_t ws_timeout_timer;

uint8_t gBuffer[BUF_LEN];
uint8_t flag_sent = 0;
size_t frameSize;
u8_t retries;
static enum wsFrameType frameType;

static struct websock_state *g_state;
static struct tcp_pcb *g_pcb;

static void
prepareBuffer(void)
{
	frameSize = BUF_LEN;
	memset(gBuffer, 0, sizeof(gBuffer));
}

void error(const char *msg)
{
    //perror(msg);
    //exit(EXIT_FAILURE);
}

void ws_timeout_callback( TimerHandle_t pxTimer )
{
    /* Release the lock */
    ws_uuid_lock[0] = 0;

    /* Turn off all relays */
    GPIO_PORTD_AHB_DATA_R = (uint32_t) ~(0x00);
    GPIO_PORTM_DATA_R = (uint32_t) ~(0x00);
}

/**
 * The connection shall be actively closed (using RST to close from fault states).
 * Reset the sent- and recv-callbacks.
 *
 * @param pcb the tcp pcb to reset callbacks
 * @param hs connection state to free
 */
static err_t
websock_close_conn(struct tcp_pcb *pcb, struct websock_state *hs, uint8_t abort_conn)
{
  err_t err;
  LWIP_DEBUGF(WEBSOCKD_DEBUG, ("Closing connection %p\n", (void*)pcb));

  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  tcp_sent(pcb, NULL);
  if (hs != NULL) {
    //http_state_free(hs);
  }

  if (abort_conn) {
    tcp_abort(pcb);
    return ERR_OK;
  }
  err = tcp_close(pcb);
  if (err != ERR_OK) {
    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("Error %d closing %p\n", err, (void*)pcb));
    /* error closing, try again later in poll */
    tcp_poll(pcb, websock_poll, 4/*HTTPD_POLL_INTERVAL*/);
  }
  return err;
}

static err_t
websock_write(struct tcp_pcb *pcb, const void* ptr, u16_t *length, u8_t apiflags)
{
   u16_t len;
   err_t err;
   LWIP_ASSERT("length != NULL", length != NULL);
   len = *length;
   if (len == 0) {
     return ERR_OK;
   }
   do {
     //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("Trying go send %d bytes\n", len));
     err = tcp_write(pcb, ptr, len, apiflags);
     if (err == ERR_MEM) {
       if ((tcp_sndbuf(pcb) == 0) ||
           (tcp_sndqueuelen(pcb) >= TCP_SND_QUEUELEN)) {
         /* no need to try smaller sizes */
         len = 1;
       } else {
         len /= 2;
       }
       LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, 
                   ("Send failed, trying less (%d bytes)\n", len));
     }
   } while ((err == ERR_MEM) && (len > 1));

   if (err == ERR_OK) {
     //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("Sent %d bytes\n", len));
   } else {
     LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("Send failed with err %d (\"%s\")\n", err, lwip_strerr(err)));
   }

   *length = len;
   return err;
}

/**
 * Try to send more data on this pcb.
 *
 * @param pcb the pcb to send data
 * @param hs connection state
 */
static u8_t
websock_send(struct tcp_pcb *pcb, struct websock_state *hs)
{
  err_t err;
  u16_t len;
  u16_t mss;
  u8_t data_to_send = 0;

  //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_send: pcb=%p hs=%p size=%d\n", (void*)pcb,
    //(void*)hs, hs != NULL ? (int)hs->size : 0));

  /* If we were passed a NULL state structure pointer, ignore the call. */
  if (hs == NULL) {
    return 0;
  }

  /* We cannot send more data than space available in the send
     buffer. */
  if (tcp_sndbuf(pcb) < hs->size) {
    len = tcp_sndbuf(pcb);
  } else {
    len = (u16_t)hs->size;
    LWIP_ASSERT("hs->size did not fit into u16_t!", (len == hs->size));
  }
  mss = tcp_mss(pcb);
  if(len > (2 * mss)) {
    len = 2 * mss;
  }
 err = websock_write(pcb, hs->frame, &len, TCP_WRITE_FLAG_COPY);
  if (err == ERR_OK) {
    data_to_send = true;
    hs->frame += len;
    hs->size -= len;
  }

  /*if (hs->size == 0)
  {
      LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("send_data end.\n"));
  }*/
  return data_to_send;
}


/**
 * The pcb had an error and is already deallocated.
 * The argument might still be valid (if != NULL).
 */
static void
websock_err(void *arg, err_t err)
{
  struct websock_state *hs = (struct websock_state *)arg;
  //LWIP_UNUSED_ARG(err);

  LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_err: %s", lwip_strerr(err)));

  if (hs != NULL) {
    //??http_state_free(hs);
  }
}

/**
 * Data has been sent and acknowledged by the remote host.
 * This means that more data can be sent.
 */
static err_t
websock_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct websock_state *hs = (struct websock_state *)arg;

    //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_sent %p\n", (void*)pcb));
    //LWIP_UNUSED_ARG(len);

    if (hs == NULL || hs->size == 0) {
	if (hs->sent_close) // A CLOSING_FRAME was sent
	{
	    hs->sent_close = 0;
	    websock_close_conn(pcb, hs, 0);
	}
	return ERR_OK;
    }
    retries = 0;
    // Checks whether there is more data to send
    if (hs->size != 0)
	websock_send(pcb, hs);

    return ERR_OK;
}

/**
 * The poll function is called every 2nd second.
 * If there has been no data sent (which resets the retries) in 8 seconds, close.
 * If the last portion of a file has not been sent in 2 seconds, close.
 *
 * This could be increased, but we don't want to waste resources for bad connections.
 */
static err_t
websock_poll(void *arg, struct tcp_pcb *pcb)
{
  struct websock_state *hs = (struct websock_state *)arg;
  //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_poll: pcb=%p hs=%p pcb_state=%s\n",
    //(void*)pcb, (void*)hs, tcp_debug_state_str(pcb->state)));

  if (hs == NULL) {
    //err_t closed;
    /* arg is null, close. */
    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_poll: arg is NULL, close\n"));
    websock_close_conn(pcb, NULL, 0);

#if LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR
    if (closed == ERR_MEM) {
       tcp_abort(pcb);
       return ERR_ABRT;
    }
#endif /* LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR */
    return ERR_OK;
  } else {
    retries++;

	if (retries == 8 && !hs->size) {
	retries = 0;
	
	#if LWIP_WEBSOCKDPING
	LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_poll: PING FRAME\n"));
	prepareBuffer();
	if (wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_PING_FRAME) == ERR_OK)
	{
	    hs->size = frameSize;
	    hs->frame = gBuffer;
	    websock_send(pcb, hs);
	    initNewFrame;
	}
	else
		return ERR_INPROGRESS;
	#endif
	
      //return ERR_OK;
    }

    /* If this connection has a file open, try to send some more data. If
     * it has not yet received a GET request, don't do this since it will
     * cause the connection to close immediately. */
    if(hs && (hs->handle || hs->size)) {
      LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_poll: try to send more data\n"));
      if(websock_send(pcb, hs)) {
        /* If we wrote anything to be sent, go ahead and send it now. */
        LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("tcp_output\n"));
        tcp_output(pcb);
      }
    }
  }

  return ERR_OK;
}

/**
 * Data has been received on this pcb.
 */
static err_t
websock_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  err_t parsed = ERR_ABRT;
  struct websock_state *hs = (struct websock_state *)arg;

  //UARTprintf("\nhttp_recv: pcb=%p pbuf=%p err=%s len=%d\n", (void*)pcb,
  //           (void*)p, lwip_strerr(err),p->tot_len);

  hs->sent_close = 0;
  g_state = hs;

  if ((err != ERR_OK) || (p == NULL) || (hs == NULL)) {
    /* error or closed by other side? */
    if (p != NULL) {
      /* Inform TCP that we have taken the data. */
      tcp_recved(pcb, p->tot_len);
      pbuf_free(p);
    }
    if (hs == NULL) {
      /* this should not happen, only to be robust */
      LWIP_DEBUGF(WEBSOCKD_DEBUG, ("Error, websock_recv: hs is NULL, close\n"));
    }
    websock_close_conn(pcb, hs, 0); //??http_close_conn(pcb, hs);
    return ERR_OK;
  }

  /* Inform TCP that we have taken the data. */
  tcp_recved(pcb, p->tot_len);

  if (hs->handle == NULL) {
    parsed = websock_parse_request(&p, hs, pcb);
  } else {
    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_recv: already sending data\n"));
  }

  if (p != NULL) {
    /* pbuf not passed to application, free it now */
    pbuf_free(p);
  }

  /* All data are send by libwebsock_send_tcp !!!!!!!!!!!!!!!
   * 
   * 
  if (parsed == ERR_OK) {
    //LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_recv: data %p len %"S32_F"\n", hs->file, hs->size));
	  websock_send(pcb, hs);
  } else 
      */
  if (parsed == ERR_ARG) {
    /* @todo: close on ERR_USE? */
    websock_close_conn(pcb, hs, 0);
  }

  return ERR_OK;
}

/** Initialize a struct websock_state.
 */
static void
websock_state_init(struct websock_state* hs)
{
  /* Initialize the structure. */
  memset(hs, 0, sizeof(struct websock_state));
}

/** Allocate a struct websock_state. */
struct websock_state*
websock_state_alloc(void)
{
  struct websock_state *ret = WEBSOCK_ALLOC_STATE();

  if (ret != NULL) {
    websock_state_init(ret);
  }
  return ret;
}

static err_t websockd_accept(void *arg, struct tcp_pcb *pcb, err_t err) // (void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct websock_state *hs;
  struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen*)arg;
  (void)lpcb;
  //LWIP_UNUSED_ARG(err);
  //LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_accept %p / %p\n", (void*)pcb, arg));
  g_pcb = pcb;

  /* Decrease the listen backlog counter */
  tcp_accepted(lpcb);
  /* Set priority */
  tcp_setprio(pcb, WEBSOCKD_TCP_PRIO);

  /* Allocate memory for the structure that holds the state of the
     connection - initialized by that function. */
  hs = websock_state_alloc();
  if (hs == NULL) {
    LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_accept: Out of memory, RST\n"));
    return ERR_MEM;
  }
  hs->pcb = pcb;

  /* Tell TCP that this is the structure we wish to be passed for our
     callbacks. */
  tcp_arg(pcb, hs);

  /* Set up the various callback functions */
  tcp_recv(pcb, websock_recv);
  tcp_err(pcb, websock_err);
  #if LWIP_WEBSOCKDPING
  tcp_poll(pcb, websock_poll, 8);
  #endif
  tcp_sent(pcb, websock_sent);

  return ERR_OK;
}
/**
 * Initialize the websocket with the specified local address.
 */
static void
websockd_init_addr(ip_addr_t *local_addr)
{
  struct tcp_pcb *pcb;
  err_t err;
  (void)err;

  pcb = tcp_new();
  LWIP_ASSERT("websockd_init: tcp_new failed", pcb != NULL);
  tcp_setprio(pcb, WEBSOCKD_TCP_PRIO);
  /* set SOF_REUSEADDR here to explicitly bind websockd to multiple interfaces */
  err = tcp_bind(pcb, local_addr, WEBSOCKD_SERVER_PORT);
  LWIP_ASSERT("websockd_init: tcp_bind failed", err == ERR_OK);
  pcb = tcp_listen(pcb);
  LWIP_ASSERT("websockd_init: tcp_listen failed", pcb != NULL);
  /* initialize callback arg and accept callback */
  tcp_arg(pcb, pcb);
  tcp_accept(pcb, websockd_accept);
}


static err_t
websock_parse_request(struct pbuf **inp, struct websock_state *whs, struct tcp_pcb *pcb)
{
    err_t err;
    int err_code;
    size_t readedLength = 0;
    static enum wsState state = WS_STATE_OPENING;
    uint8_t *data = NULL;
    size_t dataSize = 0;
    static struct handshake hs;
    struct pbuf *p = *inp;
    nullHandshake(&hs);
    frameType = WS_INCOMPLETE_FRAME;

    readedLength+= p->tot_len;
    whs->buf = (uint8_t *)mem_malloc(readedLength); 
    whs->frame = gBuffer;
	
    memcpy(whs->buf, p->payload, p->tot_len);
    if (state == WS_STATE_OPENING) {
	frameType = wsParseHandshake(whs->buf, readedLength, &hs, &err_code);
    } else {
	frameType = wsParseInputFrame(whs->buf, readedLength, &data, &dataSize, &err_code);
    }

    LWIP_DEBUGF(WEBSOCKD_DEBUG,("\nframeType = %02X\n",frameType));
    mem_free(whs->buf);

    if ((frameType == WS_INCOMPLETE_FRAME && readedLength == BUF_LEN) || frameType == WS_ERROR_FRAME) {
	if (frameType == WS_INCOMPLETE_FRAME)
	    LWIP_DEBUGF(WEBSOCKD_DEBUG,("buffer too small"));
	else
	    LWIP_DEBUGF(WEBSOCKD_DEBUG,("Error in incoming frame:%d\n",err_code));
	
	if (state == WS_STATE_OPENING) {
	    // Send bad request answer
	    prepareBuffer();
	    strcat((char *)gBuffer,"HTTP/1.1 400 Bad Request\r\n");
	    strcat((char *)gBuffer,versionField);
	    strcat((char *)gBuffer,version);
	    strcat((char *)gBuffer,"\r\n\r\n\0");
	    whs->size = strlen((char *)gBuffer);
	    //whs->frame = gBuffer;
	    libwebsock_send_tcp(gBuffer, whs->size);
	    initNewFrame;

	    if (hs.resource) {
		    mem_free(hs.resource);
		    hs.resource = NULL;
	    }
	    return ERR_OK; //break;
	} else {
	    LWIP_DEBUGF(WEBSOCKD_DEBUG,("\nERROR, Sending CLOSE Frame\n"));
	    state = WS_STATE_CLOSING;
	    err = libwebsock_close();
	}
    }

    //if (state == WS_STATE_OPENING) {
    switch (frameType) {
	case WS_OPENING_FRAME:
	{
	    if (state == WS_STATE_OPENING) {
		//LWIP_DEBUGF(WEBSOCKD_DEBUG,("hs.resource: %s\n\n", hs.resource));
		
		// if resource is right, generate answer handshake and send it
		// Types of accepted requests
		if ( (strcmp(hs.resource, "/echo") &&
			strcmp(hs.resource, "/") &&
			strcmp(hs.resource, "/?encoding=text")) != 0) {
			prepareBuffer();
			// Send error 404 - resource not found
			frameSize = sprintf((char*)gBuffer, "HTTP/1.1 404 Not Found\r\n\r\n");
			//whs->size = frameSize;
			//whs->frame = gBuffer;
			libwebsock_send_tcp(gBuffer, frameSize);
			err = ERR_OK;
			break; //ERR_OK
		}
		if ( !strcmp(hs.resource, "/echo")) {
			whs->echo_mode = 1;
		}

		prepareBuffer();
		wsGetHandshakeAnswer(&hs, gBuffer, &frameSize);
		freeHandshake(&hs);
		// Send handshake answer
		//whs->size = frameSize;
		//whs->frame = gBuffer;
		libwebsock_send_tcp(gBuffer, frameSize);

		state = WS_STATE_NORMAL;
		initNewFrame;
	    } else
		err = ERR_INPROGRESS;
	    break;
	}
	case WS_CLOSING_FRAME: 
	{
	    //LWIP_DEBUGF(WEBSOCKD_DEBUG,("\n>WS_CLOSING_FRAME"));
	    err = libwebsock_close();
	    state = WS_STATE_OPENING;
	    break;
	}
	case WS_PING_FRAME:
	{
	   err = libwebsock_pong();
	   break;
	}
	case WS_TEXT_FRAME:
	{
	    uint8_t *recievedString = NULL;
	    recievedString = malloc(dataSize+1);
	    //assert(recievedString);
	    memcpy(recievedString, data, dataSize);
	    recievedString[ dataSize ] = 0;
	    //whs->size = dataSize;
	    //whs->allocated = 1;

	    if (whs->echo_mode)
	    {
		libwebsock_send_text(recievedString, dataSize);
	    } else
	    {
		websocket_get_data((char *)recievedString, dataSize);
	    }    
	    initNewFrame;
	    break;
	}
	case WS_BINARY_FRAME:
	{
	    uint8_t *recievedString = NULL;
	    recievedString = malloc(dataSize+1);
	    memcpy(recievedString, data, dataSize);
	    recievedString[ dataSize ] = 0;
	    //whs->allocated = 1;

	    libwebsock_send_binary(recievedString, dataSize);
	    websocket_get_data((char *)recievedString, dataSize);

	    initNewFrame;
	    break;
	}
    }    
    return err;    
}

/**
 * Initialize the websockd: set up a listening PCB and bind it to the defined port
 */
void
websockd_init(void)
{
  websockd_init_addr(IP_ADDR_ANY);
  retries = 0;

  /* Create the timeout timer */
  //ws_timeout_timer = xTimerCreate("Timeout", (2500 / portTICK_PERIOD_MS), pdFALSE, NULL, ws_timeout_callback);

  /* TODO: replace with assert */
  /*
  if (ws_timeout_timer == NULL) {
      send_debug_message( "Could not create timer." , DEBUG_MESSAGE_DEFAULT );
  }
  */
}

static int 
libwebsock_send_tcp(uint8_t *frame, u32_t size)
{
    g_state->frame = frame;
    g_state->size = size;
    websock_send(g_pcb, g_state);
    return ERR_OK;
}

// Public functions

int
libwebsock_ping(void)
{
	LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_poll: PING FRAME\n"));
	prepareBuffer();
	if (wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_PING_FRAME) == ERR_OK)
	{
	    //state->size = frameSize;
	    //state->frame = gBuffer;
	    libwebsock_send_tcp(gBuffer, frameSize);
	    initNewFrame;
	}
	else
		return ERR_INPROGRESS;
	return ERR_OK;
}

int
libwebsock_pong(void)
{
	prepareBuffer();
	if (wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_PONG_FRAME) == ERR_OK)
	{
		//state->size = frameSize;
		//state->frame = gBuffer;
		libwebsock_send_tcp(gBuffer, frameSize);
		initNewFrame;
	} else
		return ERR_INPROGRESS;
	return ERR_OK;
}

int
libwebsock_close(void)
{
	prepareBuffer();
	if (wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME) == ERR_OK)
	{
		//state->size = frameSize;
		//state->sent_close = 1;
		libwebsock_send_tcp(gBuffer, frameSize);
		initNewFrame;
	} else
		return ERR_INPROGRESS;
	return ERR_OK;
}

int
libwebsock_close_with_reason(unsigned short code, const char *reason)
{
    unsigned int len;
    unsigned short code_be;
    //int ret;
    char buf[128]; //w3 spec on WebSockets API (http://dev.w3.org/html5/websockets/) says reason shouldn't be over 123 bytes.
    len = 2;
    code_be = htobe16(code);
    memcpy(buf, &code_be, 2);
    if (reason) {
        len += snprintf(buf + 2, 124, "%s", reason); // Avoid buffer overflow by safely copying
    }
    //int flags = WS_FRAGMENT_FIN | WS_OPCODE_CLOSE;
    //ret = libwebsock_send_fragment(state, buf, len, flags);
    //state->flags |= STATE_SENT_CLOSE_FRAME;
	/******************************************/
    return ERR_OK;
}

int
libwebsock_send_text_with_length(char *strdata, unsigned int payload_len)
{
    //int flags = WS_FRAGMENT_FIN | WS_OPCODE_TEXT;
    return ERR_OK; //libwebsock_send_fragment(state, strdata, payload_len, flags);
}

int
libwebsock_send_text(uint8_t *strdata, uint32_t len)
{
    int ret = ERR_OK;
    prepareBuffer();
    if (wsMakeFrame(strdata, len, gBuffer, &frameSize, WS_TEXT_FRAME) == ERR_OK)
    {
	//state->size = frameSize;
	//state->frame = gBuffer;
	libwebsock_send_tcp(gBuffer, frameSize);
	retries = 0;
    } else
	ret = ERR_INPROGRESS;
    return ret;
}

int
libwebsock_send_binary(uint8_t *in_data, unsigned int payload_len)
{
    int ret = ERR_OK;
    prepareBuffer();
    if (wsMakeFrame(in_data, payload_len, gBuffer, &frameSize, WS_BINARY_FRAME) == ERR_OK)
    {
	//state->size = frameSize;
	//state->frame = gBuffer;
	libwebsock_send_tcp(gBuffer, frameSize);
	retries = 0;
    } else
	ret = ERR_INPROGRESS;
    return ret;
}

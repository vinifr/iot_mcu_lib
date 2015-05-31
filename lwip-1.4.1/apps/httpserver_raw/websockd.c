#include "websockd.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "httpd_structs.h"
#include "lwip/tcp.h"
#include "fs.h"
#include "httpserver_raw/LDA_debug.h"
#include "lwipopts.h"

#include <string.h>
#include <stdlib.h>

#include "timers.h"
#include "inc/tm4c129xnczad.h"

#include "websocket.h"
#include "lwip/tcp_impl.h"

#include "driverlib/uartstdio.h"

#define true 		1
#define false		0

#define WEBSOCKD_SERVER_PORT 8088
#define WEBSOCKD_TCP_PRIO                      TCP_PRIO_MIN

#define HTTP_ALLOC_HTTP_STATE() (struct websock_state *)mem_malloc(sizeof(struct websock_state))

#define NUM_FILE_HDR_STRINGS 3

struct websock_state {
  struct fs_file file_handle;
  struct fs_file *handle;
  char *file;       /* Pointer to first unsent byte in buf. */

  struct tcp_pcb *pcb;
  uint8_t *buf;        /* File read buffer. */
  uint8_t *frame;
  int buf_len;      /* Size of file read buffer, buf. */
  u32_t left;       /* Number of unsent bytes in buf. */
  u8_t retries;
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
  u8_t keepalive;
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
};

static err_t websock_close_conn(struct tcp_pcb *pcb, struct websock_state *hs,uint8_t abort_conn);
//static err_t http_close_or_abort_conn(struct tcp_pcb *pcb, struct http_state *hs, u8_t abort_conn);
//static err_t http_find_file(struct http_state *hs, const char *uri, int is_09);
//static err_t http_init_file(struct http_state *hs, struct fs_file *file, int is_09, const char *uri, u8_t tag_check);
static err_t websock_poll(void *arg, struct tcp_pcb *pcb);

volatile char ws_uuid_lock[36] = {0};
TimerHandle_t ws_timeout_timer;

//#define PORT 8088
#define BUF_LEN 512//0xFFFF
#define PACKET_DUMP

#define prepareBuffer frameSize = BUF_LEN; memset(gBuffer, 0, sizeof(gBuffer));
#define initNewFrame frameType = WS_INCOMPLETE_FRAME;

uint8_t gBuffer[BUF_LEN];
uint8_t flag_sent = 0;
size_t frameSize;
static enum wsFrameType frameType;

void error(const char *msg)
{
    //perror(msg);
    //exit(EXIT_FAILURE);
}

void
ws_timeout_callback( TimerHandle_t pxTimer ) {

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
     LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("Trying go send %d bytes\n", len));
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
     LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("Sent %d bytes\n", len));
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

  LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_send: pcb=%p hs=%p left=%d\n", (void*)pcb,
    (void*)hs, hs != NULL ? (int)hs->left : 0));   

  /* If we were passed a NULL state structure pointer, ignore the call. */
  if (hs == NULL) {
    return 0;
  }
  
  UARTprintf("\n data_to_send %d\n", hs->left);
  /* We cannot send more data than space available in the send
     buffer. */
  if (tcp_sndbuf(pcb) < hs->left) {
    len = tcp_sndbuf(pcb);
  } else {
    len = (u16_t)hs->left;
    LWIP_ASSERT("hs->left did not fit into u16_t!", (len == hs->left));
  }
  mss = tcp_mss(pcb);
  if(len > (2 * mss)) {
    len = 2 * mss;
  }
 err = websock_write(pcb, hs->frame, &len, TCP_WRITE_FLAG_COPY);
  if (err == ERR_OK) {
    data_to_send = true;
    hs->frame += len;
    hs->left -= len;
  }
  
  if (hs->left == 0)
  {
      LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("send_data end.\n"));
    
  }  
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
  UARTprintf("\nwebsock_sent\n");

  if (hs == NULL || hs->left == 0) {
    return ERR_OK;
  }

  hs->retries = 0;

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
#if LWIP_WEBSOCKDPING
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
    /*closed =*/ websock_close_conn(pcb, NULL, 0);
    //LWIP_UNUSED_ARG(closed);
#if LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR
    if (closed == ERR_MEM) {
       tcp_abort(pcb);
       return ERR_ABRT;
    }
#endif /* LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR */
    return ERR_OK;
  } else {
    hs->retries++;
    if (hs->retries == 4 && !hs->left) {
	hs->retries = 0;
	LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_poll: PING FRAME\n"));
	//websock_close_conn(pcb, hs, 0); //??http_close_conn(pcb, hs);
	prepareBuffer;           
	wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_PING_FRAME);
	hs->left = frameSize;
	hs->frame = gBuffer;
	websock_send(pcb, hs);
	initNewFrame;
	
      return ERR_OK;
    }

    /* If this connection has a file open, try to send some more data. If
     * it has not yet received a GET request, don't do this since it will
     * cause the connection to close immediately. */
    if(hs && (hs->handle)) {
      LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_poll: try to send more data\n"));
      if(websock_send(pcb, hs)) {
        /* If we wrote anything to be sent, go ahead and send it now. */
        LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("tcp_output\n"));
        //UARTprintf("\ntcp_output(pcb)");
        tcp_output(pcb);        
      }
    }
  }

  return ERR_OK;
}
#endif

static err_t
websock_parse_request(struct pbuf **inp, struct websock_state *whs, struct tcp_pcb *pcb)
{
  //err_t err;
  size_t readedLength = 0;  
  static enum wsState state = WS_STATE_OPENING;
  uint8_t *data = NULL;
  size_t dataSize = 0;  
  static struct handshake hs;
  struct pbuf *p = *inp;
  //int clientSocket = 1;
  nullHandshake(&hs);
  frameType = WS_INCOMPLETE_FRAME;
  
  readedLength+= p->tot_len;
  whs->buf = (uint8_t *)mem_malloc(readedLength); 
  whs->frame = gBuffer;
      
  memcpy(whs->buf, p->payload, p->tot_len);
  if (state == WS_STATE_OPENING) {
    frameType = wsParseHandshake(whs->buf, readedLength, &hs);
  } else {
    frameType = wsParseInputFrame(whs->buf, readedLength, &data, &dataSize);
  }
  UARTprintf("\nframeType = %02X\n",frameType);  
  mem_free(whs->buf);
  
  if ((frameType == WS_INCOMPLETE_FRAME && readedLength == BUF_LEN) || frameType == WS_ERROR_FRAME) {
      if (frameType == WS_INCOMPLETE_FRAME)
          UARTprintf("buffer too small");
      else
          UARTprintf("error in incoming frame\n");
      
      if (state == WS_STATE_OPENING) {
          prepareBuffer;          
          strcat((char *)gBuffer,"HTTP/1.1 400 Bad Request\r\n");
          strcat((char *)gBuffer,versionField);
          strcat((char *)gBuffer,version);    
          strcat((char *)gBuffer,"\r\n\r\n\0");       
          frameSize = strlen((char *)gBuffer);	  
	  wsMakeFrame(NULL, frameSize, gBuffer, &frameSize, WS_TEXT_FRAME);
	  whs->left = frameSize;	  
          //safeSend(clientSocket, *whs->buf, frameSize);

          return ERR_OK; //break;
      } else {
          prepareBuffer;
          UARTprintf("\n!WS_STATE_OPENING");	  
          wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
          //if (safeSend(clientSocket, whs->buf, frameSize) == EXIT_FAILURE)
            //return ERR_MEM;//break;
	  whs->left = frameSize;
          state = WS_STATE_CLOSING;
          initNewFrame;
      }
  }
  
  if (state == WS_STATE_OPENING) {   
    if (frameType == WS_OPENING_FRAME) {
      //UARTprintf("\nWS_OPENING_FRAME");
      // if resource is right, generate answer handshake and send it
      if (strcmp(hs.resource, "/echo") != 0) {
          frameSize = sprintf((char*)gBuffer, "HTTP/1.1 404 Not Found\r\n\r\n");
	  wsMakeFrame(NULL, frameSize, gBuffer, &frameSize, WS_TEXT_FRAME);
          //safeSend(clientSocket, hs->buf, frameSize);	  
	  whs->left = frameSize;
          return ERR_OK;//break;
      }
      
      prepareBuffer;
      wsGetHandshakeAnswer(&hs, gBuffer, &frameSize);
      freeHandshake(&hs);
      whs->left = frameSize;
      //if (safeSend(clientSocket, *whs->buf, frameSize) == EXIT_FAILURE)
        //return ERR_MEM;//break;
          
      state = WS_STATE_NORMAL;
      initNewFrame;
    }
  } else {
    if (frameType == WS_CLOSING_FRAME) {
      UARTprintf("\n>WS_CLOSING_FRAME");
      if (state == WS_STATE_CLOSING) {
        UARTprintf("WS_STATE_CLOSING");
        return ERR_MEM;//break;
      } else {
        flag_sent = 1;
        prepareBuffer;
        wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
        //UARTprintf("%s\n", gBuffer);
	whs->left = frameSize;
        state = WS_STATE_OPENING;
        initNewFrame;
        //websock_close_conn(pcb, whs, 0); //tcp_abort(pcb);
      }
    } else if (frameType == WS_TEXT_FRAME) {
      uint8_t *recievedString = NULL;
      recievedString = malloc(dataSize+1);
      //assert(recievedString);
      memcpy(recievedString, data, dataSize);
      recievedString[ dataSize ] = 0;
      
      prepareBuffer;
      wsMakeFrame(recievedString, dataSize, gBuffer, &frameSize, WS_TEXT_FRAME);
      whs->left = frameSize;
      free(recievedString);
      //if (safeSend(clientSocket, hs->buf, frameSize) == EXIT_FAILURE)
          //return ERR_MEM;//break;
      initNewFrame;
    }
    //UARTprintf("!!!");
  }
  //UARTprintf("...");
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
    //UARTprintf(" 1");
    /* pbuf not passed to application, free it now */
    pbuf_free(p);
  }

  if (parsed == ERR_OK) {   
    
    LWIP_DEBUGF(WEBSOCKD_DEBUG | LWIP_DBG_TRACE, ("websock_recv: data %p len %"S32_F"\n", hs->file, hs->left));
    websock_send(pcb, hs);
  } else if (parsed == ERR_ARG) {
    UARTprintf(" 4");
    /* @todo: close on ERR_USE? */
    websock_close_conn(pcb, hs, 0); //??http_close_conn(pcb, hs);
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
static struct websock_state*
websock_state_alloc(void)
{
  struct websock_state *ret = HTTP_ALLOC_HTTP_STATE();
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  if (ret == NULL) {
    http_kill_oldest_connection(0);
    ret = HTTP_ALLOC_HTTP_STATE();
  }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  if (ret != NULL) {
    websock_state_init(ret);
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
    /* add the connection to the list */
    if (http_connections == NULL) {
      http_connections = ret;
    } else {
      struct http_state *last;
      for(last = http_connections; last->next != NULL; last = last->next);
      LWIP_ASSERT("last != NULL", last != NULL);
      last->next = ret;
    }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  }
  return ret;
}

static err_t websockd_accept(void *arg, struct tcp_pcb *pcb, err_t err) // (void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct websock_state *hs;
  struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen*)arg;
  (void)lpcb;
  //LWIP_UNUSED_ARG(err);
  LWIP_DEBUGF(WEBSOCKD_DEBUG, ("websock_accept %p / %p\n", (void*)pcb, arg));

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
 * Initialize the httpd with the specified local address.
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

/**
 * Initialize the websockd: set up a listening PCB and bind it to the defined port
 */
void
websockd_init(void)
{
  websockd_init_addr(IP_ADDR_ANY);

  /* Create the timeout timer */
  ws_timeout_timer = xTimerCreate("Timeout", (2500 / portTICK_PERIOD_MS), pdFALSE, NULL, ws_timeout_callback);

  /* TODO: replace with assert */
  if (ws_timeout_timer == NULL) {
      send_debug_message( "Could not create timer." , DEBUG_MESSAGE_DEFAULT );
  }
}


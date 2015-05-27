#include "websockd.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "httpd_structs.h"
#include "lwip/tcp.h"
#include "fs.h"
#include "httpserver_raw/LDA_debug.h"

#include <string.h>
#include <stdlib.h>

#include "timers.h"
#include "inc/tm4c129xnczad.h"

#include "websocket.h"
#include "lwip/tcp_impl.h"

#include "driverlib/uartstdio.h"

#define WEBSOCKD_SERVER_PORT 8088
#define WEBSOCKD_TCP_PRIO                      TCP_PRIO_MIN

#define HTTP_ALLOC_HTTP_STATE() (struct websock_state *)mem_malloc(sizeof(struct websock_state))

#define NUM_FILE_HDR_STRINGS 3

struct websock_state {
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  struct http_state *next;
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  struct fs_file file_handle;
  struct fs_file *handle;
  char *file;       /* Pointer to first unsent byte in buf. */

  struct tcp_pcb *pcb;
#if LWIP_HTTPD_SUPPORT_REQUESTLIST
  struct pbuf *req;
#endif /* LWIP_HTTPD_SUPPORT_REQUESTLIST */

#if LWIP_HTTPD_DYNAMIC_FILE_READ
  char *buf;        /* File read buffer. */
  int buf_len;      /* Size of file read buffer, buf. */
#endif /* LWIP_HTTPD_DYNAMIC_FILE_READ */
  u32_t left;       /* Number of unsent bytes in buf. */
  u8_t retries;
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
  u8_t keepalive;
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
#if LWIP_HTTPD_SSI
  struct http_ssi_state *ssi;
#endif /* LWIP_HTTPD_SSI */
#if LWIP_HTTPD_CGI
  char *params[LWIP_HTTPD_MAX_CGI_PARAMETERS]; /* Params extracted from the request URI */
  char *param_vals[LWIP_HTTPD_MAX_CGI_PARAMETERS]; /* Values for each extracted param */
#endif /* LWIP_HTTPD_CGI */
#if LWIP_HTTPD_DYNAMIC_HEADERS
  const char *hdrs[NUM_FILE_HDR_STRINGS]; /* HTTP headers to be sent. */
  u16_t hdr_pos;     /* The position of the first unsent header byte in the
                        current string */
  u16_t hdr_index;   /* The index of the hdr string currently being sent. */
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
#if LWIP_HTTPD_TIMING
  u32_t time_started;
#endif /* LWIP_HTTPD_TIMING */
#if LWIP_HTTPD_SUPPORT_POST
  u32_t post_content_len_left;
#if LWIP_HTTPD_POST_MANUAL_WND
  u32_t unrecved_bytes;
  u8_t no_auto_wnd;
  u8_t post_finished;
#endif /* LWIP_HTTPD_POST_MANUAL_WND */
#endif /* LWIP_HTTPD_SUPPORT_POST*/
};

volatile char ws_uuid_lock[36] = {0};
TimerHandle_t ws_timeout_timer;

//#define PORT 8088
#define BUF_LEN 0xFFFF
#define PACKET_DUMP

uint8_t gBuffer[BUF_LEN];
uint8_t flag_sent = 0;


void error(const char *msg)
{
    //perror(msg);
    //exit(EXIT_FAILURE);
}

int safeSend(int clientSocket, const uint8_t *buffer, size_t bufferSize)
{
//  UARTprintf("\n*******************************\n");
//  UARTprintf(buffer);
//  UARTprintf("\n*******************************\n");  
  return EXIT_SUCCESS;
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
 * Try to send more data on this pcb.
 *
 * @param pcb the pcb to send data
 * @param hs connection state
 */
static u8_t
websock_send(struct tcp_pcb *pcb, struct websock_state *hs)
{
  u8_t data_to_send = 0;//HTTP_NO_DATA_TO_SEND;

  //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_send: pcb=%p hs=%p left=%d\n", (void*)pcb,
  //  (void*)hs, hs != NULL ? (int)hs->left : 0));
  //UARTprintf("\nhttp_send: pcb=%p hs=%p left=%d", (void*)pcb,(void*)hs, hs != NULL ? (int)hs->left : 0);  

#if LWIP_HTTPD_SUPPORT_POST && LWIP_HTTPD_POST_MANUAL_WND
  if (hs->unrecved_bytes != 0) {
    return 0;
  }
#endif /* LWIP_HTTPD_SUPPORT_POST && LWIP_HTTPD_POST_MANUAL_WND */

  /* If we were passed a NULL state structure pointer, ignore the call. */
  if (hs == NULL) {
    return 0;
  }

#if LWIP_HTTPD_FS_ASYNC_READ
  /* Check if we are allowed to read from this file.
     (e.g. SSI might want to delay sending until data is available) */
  if (!fs_is_file_ready(hs->handle, http_continue, hs)) {
    return 0;
  }
#endif /* LWIP_HTTPD_FS_ASYNC_READ */

#if LWIP_HTTPD_DYNAMIC_HEADERS
  /* Do we have any more header data to send for this file? */
//  if(hs->hdr_index < NUM_FILE_HDR_STRINGS) {
//    data_to_send = http_send_headers(pcb, hs);
//    if (data_to_send != HTTP_DATA_TO_SEND_CONTINUE) {
//      return data_to_send;
//    }
//  }
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

  /* Have we run out of file data to send? If so, we need to read the next
   * block from the file. */
  if (hs->left == 0) {
//    if (!http_check_eof(pcb, hs)) {
//      return 0;
//    }
  }

#if LWIP_HTTPD_SSI
  if(hs->ssi) {
//    data_to_send = http_send_data_ssi(pcb, hs);
  } else
#endif /* LWIP_HTTPD_SSI */
  {
    UARTprintf("\ndata_to_send %d",strlen(gBuffer));
    //UARTprintf("\n*******************************\n");
    //UARTprintf(gBuffer);
    //UARTprintf("\n*******************************\n");
    /* push to buffer */
    //tcp_ack_now(pcb);
    //tcp_output(pcb);
    tcp_write(pcb, gBuffer, strlen(gBuffer), TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
//    data_to_send = http_send_data_nonssi(pcb, hs);
  }

//  if((hs->left == 0) && (fs_bytes_left(hs->handle) <= 0)) {
    /* We reached the end of the file so this request is done.
     * This adds the FIN flag right into the last data segment. */
//    LWIP_DEBUGF(HTTPD_DEBUG, ("End of file.\n"));
//    http_eof(pcb, hs);
//    return 0;
//  }
//  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("send_data end.\n"));
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

  //LWIP_DEBUGF(HTTPD_DEBUG, ("http_err: %s", lwip_strerr(err)));

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

  //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_sent %p\n", (void*)pcb));

  //LWIP_UNUSED_ARG(len);
  UARTprintf("\nwebsock_sent");

  if (hs == NULL) {
    return ERR_OK;
  }

  hs->retries = 0;

  //if(flag_sent) 
  //websock_send(pcb, hs);

  flag_sent = 0;
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
  //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_poll: pcb=%p hs=%p pcb_state=%s\n",
  //  (void*)pcb, (void*)hs, tcp_debug_state_str(pcb->state)));

  if (hs == NULL) {
    err_t closed;
    /* arg is null, close. */
    //LWIP_DEBUGF(HTTPD_DEBUG, ("http_poll: arg is NULL, close\n"));
    //??closed = http_close_conn(pcb, NULL);
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
    if (hs->retries == 4/*??HTTPD_MAX_RETRIES*/) {
      //LWIP_DEBUGF(HTTPD_DEBUG, ("http_poll: too many retries, close\n"));
      //??http_close_conn(pcb, hs);
      return ERR_OK;
    }

    /* If this connection has a file open, try to send some more data. If
     * it has not yet received a GET request, don't do this since it will
     * cause the connection to close immediately. */
    if(hs && (hs->handle)) {
      //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_poll: try to send more data\n"));
      if(websock_send(pcb, hs)) {
        /* If we wrote anything to be sent, go ahead and send it now. */
        //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("tcp_output\n"));
        UARTprintf("\ntcp_output(pcb)");
        tcp_output(pcb);
      }
    }
  }

  return ERR_OK;
}

static err_t
websock_parse_request(struct pbuf **inp, struct websock_state *whs, struct tcp_pcb *pcb)
{
  err_t err;
  size_t readedLength = 0;
  size_t frameSize = BUF_LEN;
  static enum wsState state = WS_STATE_OPENING;
  uint8_t *data = NULL;
  size_t dataSize = 0;
  static enum wsFrameType frameType = WS_INCOMPLETE_FRAME;
  static struct handshake hs;
  struct pbuf *p = *inp;
  int clientSocket = 1;
  nullHandshake(&hs);
  
  #define prepareBuffer frameSize = BUF_LEN; memset(gBuffer, 0, BUF_LEN);
  #define initNewFrame frameType = WS_INCOMPLETE_FRAME; //readedLength = 0; memset(gBuffer, 0, BUF_LEN);
  
  readedLength+= p->tot_len;
  memcpy(gBuffer, p->payload, p->tot_len);
  if (state == WS_STATE_OPENING) {
    frameType = wsParseHandshake(gBuffer, readedLength, &hs);
  } else {
    frameType = wsParseInputFrame(gBuffer, readedLength, &data, &dataSize);
  }
  UARTprintf("\nframeType = %02X",frameType);
  if ((frameType == WS_INCOMPLETE_FRAME && readedLength == BUF_LEN) || frameType == WS_ERROR_FRAME) {
      if (frameType == WS_INCOMPLETE_FRAME)
          UARTprintf("buffer too small");
      else
          UARTprintf("error in incoming frame\n");
      
      if (state == WS_STATE_OPENING) {
          prepareBuffer;
          //UARTprintf("\nWS_STATE_OPENING");
          //frameSize = sprintf((char *)gBuffer,
          //                    "HTTP/1.1 400 Bad Request\r\n"
          //                    "%s%s\r\n\r\n",
          //                    versionField,
          //                    version);
          strcat((char *)gBuffer,"HTTP/1.1 400 Bad Request\r\n");
          strcat((char *)gBuffer,versionField);
          strcat((char *)gBuffer,version);    
          strcat((char *)gBuffer,"\r\n\r\n\0");       
          frameSize = strlen((char *)gBuffer);
          safeSend(clientSocket, gBuffer, frameSize);

          return;//break;
      } else {
          prepareBuffer;
          UARTprintf("\n!WS_STATE_OPENING");
          wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
          if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
            return;//break;
          state = WS_STATE_CLOSING;
          initNewFrame;
      }
  }
  
  if (state == WS_STATE_OPENING) {
    //UARTprintf("\nWS_STATE_OPENING");
    //assert(frameType == WS_OPENING_FRAME);
    if (frameType == WS_OPENING_FRAME) {
      //UARTprintf("\nWS_OPENING_FRAME");
      // if resource is right, generate answer handshake and send it
      if (strcmp(hs.resource, "/echo") != 0) {
          frameSize = sprintf((char *)gBuffer, "HTTP/1.1 404 Not Found\r\n\r\n");
          safeSend(clientSocket, gBuffer, frameSize);
          return;//break;
      }
      
      prepareBuffer;
      wsGetHandshakeAnswer(&hs, gBuffer, &frameSize);
      freeHandshake(&hs);
      if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
        return;//break;
          
      state = WS_STATE_NORMAL;
      initNewFrame;
    }
  } else {
    if (frameType == WS_CLOSING_FRAME) {
      UARTprintf("\n>WS_CLOSING_FRAME");
      if (state == WS_STATE_CLOSING) {
        UARTprintf("WS_STATE_CLOSING");
        return;//break;
      } else {
        //uint8_t *recievedString = NULL;
        //recievedString = malloc(dataSize+1);

        ///memcpy(recievedString, data, dataSize);
        //recievedString[ dataSize ] = 0;
        
        //prepareBuffer;
        //wsMakeFrame(recievedString, dataSize, gBuffer, &frameSize, WS_CLOSING_FRAME);
        //free(recievedString);
        //if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
        //    return;//break;
        //initNewFrame; 
        flag_sent = 1;
        prepareBuffer;
        wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
        UARTprintf(gBuffer);
        state = WS_STATE_OPENING;
        initNewFrame;
        tcp_abort(pcb);
      }
    } else if (frameType == WS_TEXT_FRAME) {
      uint8_t *recievedString = NULL;
      recievedString = malloc(dataSize+1);
      //assert(recievedString);
      memcpy(recievedString, data, dataSize);
      recievedString[ dataSize ] = 0;
      
      prepareBuffer;
      wsMakeFrame(recievedString, dataSize, gBuffer, &frameSize, WS_TEXT_FRAME);
      free(recievedString);
      if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
          return;//break;
      initNewFrame;
    }
    //UARTprintf("!!!");
  }
  //UARTprintf("...");
  return ERR_OK;
}

/**
 * Data has been received on this pcb.
 * For HTTP 1.0, this should normally only happen once (if the request fits in one packet).
 */
static err_t
websock_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  err_t parsed = ERR_ABRT;
  struct websock_state *hs = (struct websock_state *)arg;

  //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_recv: pcb=%p pbuf=%p err=%s\n", (void*)pcb,
  //  (void*)p, lwip_strerr(err)));
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
      //LWIP_DEBUGF(HTTPD_DEBUG, ("Error, http_recv: hs is NULL, close\n"));
    }
    //??http_close_conn(pcb, hs);
    return ERR_OK;
  }

#if LWIP_HTTPD_SUPPORT_POST && LWIP_HTTPD_POST_MANUAL_WND
  if (hs->no_auto_wnd) {
     hs->unrecved_bytes += p->tot_len;
  } else
#endif /* LWIP_HTTPD_SUPPORT_POST && LWIP_HTTPD_POST_MANUAL_WND */
  {
    /* Inform TCP that we have taken the data. */
    tcp_recved(pcb, p->tot_len);
  }

#if LWIP_HTTPD_SUPPORT_POST
  if (hs->post_content_len_left > 0) {
    /* reset idle counter when POST data is received */
    hs->retries = 0;
    /* this is data for a POST, pass the complete pbuf to the application */
    //??http_post_rxpbuf(hs, p);
    /* pbuf is passed to the application, don't free it! */
    if (hs->post_content_len_left == 0) {
      /* all data received, send response or close connection */
      //??http_send(pcb, hs);
    }
    return ERR_OK;
  } else
#endif /* LWIP_HTTPD_SUPPORT_POST */
  {
    struct evbuffer *input;
    struct bufferevent *bev;
    if (hs->handle == NULL) {
      //UARTprintf("\nparse_request:");
      //UARTprintf("\n%s", p->payload);
      
      //clientWorker(1,p->tot_len, p->payload);
      parsed = websock_parse_request(&p, hs, pcb);
      
      //LWIP_ASSERT("http_parse_request: unexpected return value", parsed == ERR_OK
      //  || parsed == ERR_INPROGRESS ||parsed == ERR_ARG || parsed == ERR_USE);
    } else {
      //LWIP_DEBUGF(HTTPD_DEBUG, ("http_recv: already sending data\n"));
    }
#if LWIP_HTTPD_SUPPORT_REQUESTLIST
    if (parsed != ERR_INPROGRESS) {
      /* request fully parsed or error */
      if (hs->req != NULL) {
        //??pbuf_free(hs->req);
        hs->req = NULL;
      }
    }
#else /* LWIP_HTTPD_SUPPORT_REQUESTLIST */
    if (p != NULL) {
      //UARTprintf(" 1");
      /* pbuf not passed to application, free it now */
      pbuf_free(p);
    }
#endif /* LWIP_HTTPD_SUPPORT_REQUESTLIST */
    if (parsed == ERR_OK) {
      //UARTprintf(" 2");
#if LWIP_HTTPD_SUPPORT_POST
      if (hs->post_content_len_left == 0)
#endif /* LWIP_HTTPD_SUPPORT_POST */
      {
        UARTprintf(" 3");
        //LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_recv: data %p len %"S32_F"\n", hs->file, hs->left));
        websock_send(pcb, hs);
      }
      
    } else if (parsed == ERR_ARG) {
      UARTprintf(" 4");
      /* @todo: close on ERR_USE? */
      //??http_close_conn(pcb, hs);
    }
    //UARTprintf(" 5");
  }
  //UARTprintf(" 6");
  return ERR_OK;
}

/** Initialize a struct websock_state.
 */
static void
websock_state_init(struct websock_state* hs)
{
  /* Initialize the structure. */
  memset(hs, 0, sizeof(struct websock_state));
#if LWIP_HTTPD_DYNAMIC_HEADERS
  /* Indicate that the headers are not yet valid */
  hs->hdr_index = NUM_FILE_HDR_STRINGS;
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
}

/** Allocate a struct http_state. */
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

websockd_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct websock_state *hs;
  struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen*)arg;
  (void)lpcb;
  //LWIP_UNUSED_ARG(err);
  //LWIP_DEBUGF(HTTPD_DEBUG, ("http_accept %p / %p\n", (void*)pcb, arg));

  /* Decrease the listen backlog counter */
  tcp_accepted(lpcb);
  /* Set priority */
  tcp_setprio(pcb, WEBSOCKD_TCP_PRIO);

  /* Allocate memory for the structure that holds the state of the
     connection - initialized by that function. */
  hs = websock_state_alloc();
  if (hs == NULL) {
  //  LWIP_DEBUGF(HTTPD_DEBUG, ("http_accept: Out of memory, RST\n"));
    return ERR_MEM;
  }
  hs->pcb = pcb;

  /* Tell TCP that this is the structure we wish to be passed for our
     callbacks. */
  tcp_arg(pcb, hs);

  /* Set up the various callback functions */
  tcp_recv(pcb, websock_recv);
  tcp_err(pcb, websock_err);
  tcp_poll(pcb, websock_poll, 4/*HTTPD_POLL_INTERVAL*/);
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
  LWIP_ASSERT("httpd_init: tcp_new failed", pcb != NULL);
  tcp_setprio(pcb, WEBSOCKD_TCP_PRIO);
  /* set SOF_REUSEADDR here to explicitly bind httpd to multiple interfaces */
  err = tcp_bind(pcb, local_addr, WEBSOCKD_SERVER_PORT);
  //LWIP_ASSERT("httpd_init: tcp_bind failed", err == ERR_OK);
  pcb = tcp_listen(pcb);
  //LWIP_ASSERT("httpd_init: tcp_listen failed", pcb != NULL);
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

#ifndef __WEBSOCKD_H__
#define __WEBSOCKD_H__

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"

#include "lwip/debug.h"
#include "lwip/stats.h"
#include "httpd_structs.h"
#include "lwip/tcp.h"
#include "fs.h"
#include "httpserver_raw/LDA_debug.h"
#include "lwip/tcp_impl.h"
#include "main.h"

struct websock_state {
  struct fs_file file_handle;
  struct fs_file *handle;
  char *file;       /* Pointer to first unsent byte in buf. */
  char sent_close;
  char echo_mode;
  char allocated;

  struct tcp_pcb *pcb;
  uint8_t *buf;        /* File read buffer. */
  uint8_t *frame;
  int buf_len;      /* Size of file read buffer, buf. */
  u32_t size;       /* Number of unsent bytes in buf. */
  u8_t retries;
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
  u8_t keepalive;
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
};

void websockd_init(void);
struct websock_state* websock_state_alloc(void);

// Public functions
int libwebsock_ping(void);
int libwebsock_pong(void);
int libwebsock_close(void);
int libwebsock_close_with_reason(unsigned short code, const char *reason);
int libwebsock_send_text_with_length(char *strdata, unsigned int payload_len);
int libwebsock_send_text(uint8_t *strdata, uint32_t len);
int libwebsock_send_binary(uint8_t *in_data, unsigned int payload_len);
#endif /* __WEBSOCKD_H__ */



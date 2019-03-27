/* Much of the following code was copied from libevent-client.c from the
 * nghttp2 library.  See:
 *
 *     https://nghttp2.org/documentation/tutorial-client.html
 */
#include <nghttp2/nghttp2.h>
#include "pbc-grpc.h"

typedef struct PBC_GRPC_ClientService PBC_GRPC_ClientService;
typedef struct PBC_GRPC_Client_SessionData PBC_GRPC_Client_SessionData;
typedef struct PBC_GRPC_Client_StreamData PBC_GRPC_Client_StreamData;

struct PBC_GRPC_Client
{
  unsigned magic;
  unsigned ref_count;

  PBC_GRPC_Dispatch *dispatch;

  //
  // Information parsed from the input URI.
  //
  // This information is mostly validated in the constructor.
  //
  char *url_scheme, *url_host, *url_path;
  char *url_query;           // optional: if it is set it must include the initial '?'
  int url_port;              // -1 if not set
  bool url_secure;           // if https, basically.

  //
  // A list of services, sorted by 'name' on demand.
  //
  // Sorted on demand; add in sorted-order to minimize costs.
  //
  unsigned n_services;
  PBC_GRPC_ClientService **services;
  unsigned services_allocated;
  bool services_sorted;

  //
  // The primary session.
  //
  PBC_GRPC_Client_SessionData *session;

  //
  // Sessions that have received the GO_AWAY message,
  // but still have live streams.
  //
  // These should be very few in number.
  // 
  unsigned n_dead_sessions;
  PBC_GRPC_Client_SessionData **dead_sessions;
};

//
// NOTE: this structure is cast to a ProtobufCService.
//
struct PBC_GRPC_ClientService
{
  ProtobufCService base_service;
  unsigned magic;
  PBC_GRPC_Client *owner;

  ..
};

struct PBC_GRPC_Client_SessionData
{
  SSL *ssl_stream;                      // if ssl
  int fd;
  bool got_go_away;                     // whether this is in the dead_sessions array

  PBC_GRPC_Client_SessionData *first_stream, *last_stream;
} PBC_GRPC_Client_SessionData;

struct PBC_GRPC_Client_StreamData
{
  PBC_GRPC_Client_SessionData *owner;
  PBC_GRPC_Client_StreamData *prev_stream_in_owner;
  PBC_GRPC_Client_StreamData *next_stream_in_owner;
};

static int
select_next_proto_cb(SSL *ssl,
                     unsigned char **out,
                     unsigned char *outlen,
                     const unsigned char *in,
                     unsigned int inlen,
                     void *arg) {
  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
  }
  return SSL_TLSEXT_ERR_OK;
}



static int 
bio_pbc_grpc_bwrite (BIO *bio, const char *out, int length)
{
  PBC_GRPC_Client_SessionData *session_data = bio->ptr;
  BIO_clear_retry_flags (bio);
  int write_rv = write (session_data->fd, out, len);
  if (write_rv < 0)
    {
      if (errno == EINTR)
        return 0;
      int e = errno;
      session_error (session_data, "error writing to fd: %s", strerror(e));
      errno = e;
      return -1;
    }

  return write_rv;
}

static int 
bio_pbc_grpc_bread (BIO *bio, char *in, int max_length)
{
  PBC_GRPC_Client_SessionData *session_data = bio->ptr;
  unsigned n_read;
  BIO_clear_retry_flags (bio);
  ssize_t nread = read (session_data->fd, in, max_length);
  if (nread == 0)
    return 0;
  else if (nread > 0)
    return nread;
  else
    {
      int e = errno;
      session_error (session_data, "error reading from fd: %s", strerror(e));
      errno = e;
      return -1;
    }
}

static long 
bio_pbc_grpc_ctrl (BIO  *bio,
              int   cmd,
              long  num,
              void *ptr)
{
  DskSslStream *stream = DSK_SSL_STREAM (bio->ptr);
  DSK_UNUSED (stream);
  DSK_UNUSED (num);
  DSK_UNUSED (ptr);

  //DEBUG_BIO("bio_pbc_grpc_ctrl: called with cmd=%d", cmd);

  switch (cmd)
    {
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
      return 1;
    }

  /* -1 seems more appropriate, but this is
     what bss_fd returns when it doesn't know the cmd. */
  return 0;
}

static int 
bio_pbc_grpc_create (BIO *bio)
{
  DSK_UNUSED (bio);
  // DEBUG_BIO("bio_pbc_grpc_create (%p)", bio);
  return 1;
}

static int 
bio_pbc_grpc_destroy (BIO *bio)
{
  PBC_GRPC_Client_SessionData *session_data = bio->ptr;
  (void) session_data;
  return 1;
}


static BIO_METHOD pbc_grpc_client_bio_method =
{
  22,                               /* type:  this is quite a hack */
  "PBC_GRPC_Client",                /* name */
  bio_pbc_grpc_client_bwrite,       /* bwrite */
  bio_pbc_grpc_client_bread,        /* bread */
  NULL,                             /* bputs */
  NULL,                             /* bgets */
  bio_pbc_grpc_client_ctrl,         /* ctrl */
  bio_pbc_grpc_client_create,       /* create */
  bio_pbc_grpc_client_destroy,      /* destroy */
  NULL                              /* callback_ctrl */
};


static void
session_connected (PBC_GRPC_Client_SessionData *session)
{
  PBC_GRPC_Events events = 0;
  if (client->ssl_ctx != NULL)
    {
      rv->ssl = SSL_new(ssl_ctx);
      BIO *bio = BIO_new (&pbc_grpc_client_bio_method);
      bio->ptr = session_data;
      bio->init = 1;
      SSL_set_bio(rv->ssl, bio, bio);
      SSL_set_connect_state(rv->ssl);

      if (SSL_wants_read (rv->ssl))
        events = PBC_GRPC_EVENT_READABLE;
      else if (SSL_wants_write (rv->ssl))
        events = PBC_GRPC_EVENT_WRITABLE;

      pbc_grpc_dispatch_watch_fd (client->dispatch, rv->fd, events,
                                  handle_raw_io, rv);

    }
  else
    {
      // defer to nghttp2
      events = ...;
    }
  pbc_grpc_dispatch_watch_fd (client->dispatch, fd, events,
                              handle_connected_nonssl, rv);
}

static void
pbc_grpc_dns_lookup (PBC_GRPC_Dispatch   *dispatch,
                     const char          *hostname,
                     DNSResolutionHandler handler,
                     void                *data)
{
}

static PBC_GRPC_Client_SessionData *
initiate_connection(PBC_GRPC_Client *client,
                    PBC_GRPC_Error **error)
{
  int rv;
  struct bufferevent *bev;
  SSL *ssl;
  PBC_GRPC_Client_SessionData *rv = NEW0 (PBC_GRPC_Client_SessionData);

  if (has_numeric_address (client, &saddr))
    {
      switch (new_connecting_raw (&saddr, &rv->fd))
        {
        case CLIENT_CONNECT_CONNECTING:
          rv->state = STATE_CONNECTING;
          pbc_grpc_dispatch_watch_fd (client->dispatch, rv->fd,
                                      PBC_GRPC_EVENT_READABLE | PBC_GRPC_EVENT_WRITABLE,
                                      handle_connected_nonssl, rv);
          break;
        case CLIENT_CONNECT_CONNECTED:
          rv->state = STATE_CONNECTED;
          session_connected (rv);
          break;
        case CLIENT_CONNECT_ERROR:
          *error = ...;
          free (rv);
          return NULL;
        }
      ... append to un-handshaked list
    }
  else
    {
      rv->state = STATE_RESOLVING;
      ... append to pending_dns list in 
      if (!client->is_resolving_dns)
        {
          client->is_resolving_dns = true;
          pbc_grpc_dns_lookup (client->host, handle_dns_resolution, client);
        }
    }

}



PBC_GRPC_Client *
pbc_grpc_client_new (PBC_GRPC_Dispatch *dispatch,
                     const char *url,
                     PBC_GRPC_Client_New_Options *options);


/*
 * Create a service that uses this client.
 *
 * Use protobuf_c_service_destroy() to unregister the service.
 * (This will not interfere with running requests to this service.)
 */
ProtobufCService *
pbc_grpc_client_create_service (PBC_GRPC_Dispatch *dispatch,
                                PBC_GRPC_Client *client,
                                ProtobufCServiceDescriptor *desc);


void
pbc_grpc_client_destroy (PBC_GRPC_Client *client);


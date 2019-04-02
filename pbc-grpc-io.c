/*
 * PBC_GRPC_IO:  A bi-directional data stream.
 *
 * This provides an implementation of
 * PBC_GRPC_IOSystem that uses:
 *    * usual POSIX API for file-descriptors and sockets
 *    * a tiny in-library DNS resolver
 *    * OpenSSL to build secure connections from raw connections
 */

#include "pbc-grpc-io.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

typedef struct {
  PBC_GRPC_IOSystem base_system;
  PBC_GRPC_Dispatch *dispatch;
} DispatchBasedIOSystem;


/* --- Dispatch-Based Raw Client --- */
typedef enum
/*
 *  ----------------------------
 * --------- Raw Client ---------
 *  ----------------------------
 */
{
  IO_RAW_CLIENT_INIT,    // only temporarily during construction
  IO_RAW_CLIENT_DOING_NAME_LOOKUP,
  IO_RAW_CLIENT_IS_CONNECTING,
  IO_RAW_CLIENT_IS_CONNECTED,
  IO_RAW_CLIENT_FAILED,
  IO_RAW_CLIENT_DESTROYED,
  IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP
} IORawClientState;

typedef struct IORawClient IORawClient;
struct IORawClient
{
  PBC_GRPC_IO          base_io;
  PBC_GRPC_Dispatch   *dispatch;
  IORawClientState     state;
  int                  fd;
  PBC_GRPC_IOFunc      readable;
  PBC_GRPC_IOFunc      writable;
  PBC_GRPC_IOErrorFunc error;
  void                *callback_data;
};

static void
handle_io_raw_client_events  (PBC_GRPC_FD   fd,
                              unsigned       events,
                              void          *callback_data)
{
  IORawClient *io_rc = callback_data;
  if ((events & PBC_GRPC_EVENT_READABLE) != 0
   && io_rc->readable != NULL)
    io_rc->readable (&io_rc->base_io, io_rc->callback_data);
  if ((events & PBC_GRPC_EVENT_WRITABLE) != 0
   && io_rc->writable != NULL)
    io_rc->writable (&io_rc->base_io, io_rc->callback_data);
}

static inline int
compute_events_from_callback (IORawClient *io_rc)
{
  int events = 0;
  return ((io_rc->readable != NULL) ? PBC_GRPC_EVENT_READABLE : 0)
       | ((io_rc->writable != NULL) ? PBC_GRPC_EVENT_WRITABLE : 0);
}

static void
io_raw_client_set_wants (PBC_GRPC_IO    *io,
                         PBC_GRPC_IOFunc readable,
                         PBC_GRPC_IOFunc writable,
                         PBC_GRPC_IOErrorFunc error,
                         void           *callback_data)
{
  IORawClient *io_rc = (IORawClient *) io;
  io_rc->readable = readable;
  io_rc->writable = writable;
  io_rc->error = error;
  io_rc->callback_data = callback_data;
  if (io_rc->fd >= 0)
    pbc_grpc_dispatch_watch_fd (io_rc->dispatch,
                                io_rc->fd,
                                compute_events_from_callback (io_rc),
                                handle_io_raw_client_events,
                                io_rc);
}

static PBC_GRPC_IO_Result
io_raw_client_read      (PBC_GRPC_IO    *io,
                         size_t          size,
                         uint8_t        *data)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  ssize_t read_rv;
  PBC_GRPC_IO_Result rv;

  switch (io_raw_client->state)
    {
    case IO_RAW_CLIENT_INIT:
      assert(false);
    case IO_RAW_CLIENT_DOING_NAME_LOOKUP:
    case IO_RAW_CLIENT_IS_CONNECTING:
      rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return rv;
    case IO_RAW_CLIENT_IS_CONNECTED:
      break;
    case IO_RAW_CLIENT_FAILED:
      rv.code = PBC_GRPC_IO_RESULT_ERROR;
      rv.error = pbc_grpc_error_new ("cannot read: client-connection failed");
      return rv;
    case IO_RAW_CLIENT_DESTROYED:
    case IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP:
      rv.code = PBC_GRPC_IO_RESULT_EOF;
      return rv;
    }

do_sys_read:
  read_rv = read (io_raw_client->fd, data, size);
  if (read_rv < 0)
    {
      if (errno == EINTR)
        goto do_sys_read;
      if (errno == EAGAIN)
        {
          rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
        }
      else
        {
          rv.code = PBC_GRPC_IO_RESULT_ERROR;
          rv.error = pbc_grpc_error_new_printf ("error reading fd %d: %s",
                                                io_raw_client->fd,
                                                strerror(errno));
        }
    }
  else if (read_rv == 0)
    {
      rv.code = PBC_GRPC_IO_RESULT_EOF;
    }
  else if (read_rv < size)
    {
      rv.code = PBC_GRPC_IO_RESULT_PARTIAL;
      rv.partial.amount = read_rv;
    }
  else
    {
      rv.code = PBC_GRPC_IO_RESULT_SUCCESS;
    }
  return rv;
}

static PBC_GRPC_IO_Result
io_raw_client_write     (PBC_GRPC_IO    *io,
                         size_t          size,
                         const uint8_t  *data)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  ssize_t write_rv;
  PBC_GRPC_IO_Result rv;

  switch (io_raw_client->state)
    {
    case IO_RAW_CLIENT_DOING_NAME_LOOKUP:
    case IO_RAW_CLIENT_IS_CONNECTING:
      rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return rv;
    case IO_RAW_CLIENT_IS_CONNECTED:
      break;
    case IO_RAW_CLIENT_FAILED:
      rv.code = PBC_GRPC_IO_RESULT_ERROR;
      rv.error = pbc_grpc_error_new ("cannot write: client-connection failed");
      return rv;
    case IO_RAW_CLIENT_DESTROYED:
    case IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP:
      rv.code = PBC_GRPC_IO_RESULT_EOF;
      return rv;
    }

do_sys_write:
  write_rv = write (io_raw_client->fd, data, size);
  if (write_rv < 0)
    {
      if (errno == EINTR)
        goto do_sys_write;
      // TODO: perhaps EPIPE should be treated as EOF?
      if (errno == EAGAIN)
        {
          rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
        }
      else
        {
          rv.code = PBC_GRPC_IO_RESULT_ERROR;
          rv.error = pbc_grpc_error_new_printf ("error writing fd %d: %s",
                                                io_raw_client->fd,
                                                strerror(errno));
        }
    }
  else if (write_rv == 0)
    {
      rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
    }
  else if (read_rv < size)
    {
      rv.code = PBC_GRPC_IO_RESULT_PARTIAL;
      rv.partial.amount = read_rv;
    }
  else
    {
      rv.code = PBC_GRPC_IO_RESULT_SUCCESS;
    }
  return rv;
}

static void
io_raw_client_destroy   (PBC_GRPC_IO *io)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  if (io_raw_client->fd >= 0)
    {
      pbc_grpc_dispatch_close_fd (io_raw_client->dispatch, io_raw_client->fd);
      io_raw_client->fd = -1;
    }
  assert (io_raw_client->state != IO_RAW_CLIENT_DESTROYED
   &&     io_raw_client->state != IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP);
  if (io_raw_client->state = IO_RAW_CLIENT_DOING_NAME_LOOKUP)
    io_raw_client->state = IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP;
  else
    io_raw_client->state = IO_RAW_CLIENT_DESTROYED;
}

static char *
io_raw_client_status_as_string (PBC_GRPC_IO    *io)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  struct sockaddr us, them;
  socklen_t us_len = sizeof(us), them_len = sizeof(them);
  char *us_name = NULL, *them_name = NULL;
  if (io_raw_client->fd >= 0)
    {
      getpeername (io_raw_client->fd, &us, &us_len);
      getsockname (io_raw_client->fd, &them, &them_len);
      us_name = sockaddr_as_string (us_len, &us);
      them_name = sockaddr_as_string (them_len, &them);
    }
  char *rv = NULL;
  switch (io_raw_client->state)
    {
    case IO_RAW_CLIENT_DOING_NAME_LOOKUP:
      rv = strdup ("raw-client: doing name-lookup");
      break;
    case IO_RAW_CLIENT_IS_CONNECTING:
      rv = pbc_grpc_strdup_printf ("raw-client: %s connecting to %s",
                                   us_name, them_name);
      break;
    case IO_RAW_CLIENT_IS_CONNECTED:
      rv = pbc_grpc_strdup_printf ("raw-client: %s connected to %s",
                                   us_name, them_name);
      break;
    case IO_RAW_CLIENT_FAILED:
      rv = pbc_grpc_strdup_printf ("raw-client: failed");
      break;
    case IO_RAW_CLIENT_DESTROYED:
    case IO_RAW_CLIENT_DESTROYED_DURING_DNS_LOOKUP:
      rv = pbc_grpc_strdup_printf ("raw-client: closed");
      break;
    }
  if (us_name != NULL)
    {
      free (us_name);
      free (them_name);
    }
  return rv;
}
static PBC_GRPC_IO_Class pbc_grpc_io_raw_client_class =
{
  "RawClient",
  io_raw_client_set_wants,
  io_raw_client_read,
  io_raw_client_write,
  io_raw_client_destroy,
  io_raw_client_status_as_string
};

static void
client_handle_is_connecting (PBC_GRPC_FD   fd,
                             unsigned       events,
                             void          *callback_data)
{
  IORawClient *io_raw_client = (IORawClient *) callback_data;
retry_getsockopt:
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &e) != 0)
    {
      if (errno == EINTR)
        goto retry_getsockopt;
      ...
    }
  if (e != 0)
    {
      PBC_GRPC_Error *error;
      error = pbc_grpc_error_new_printf ("connecting socket failure: %s",
                                         strerror (e));
      if (io_raw_client->error == NULL)
        fprintf(stderr, "unhandled connecting error: %s\n", error->message);
      else
        io_raw_client->error (error, io_raw_client->callback_data);
      pbc_grpc_dispatch_close_fd (io_raw_client->dispatch, fd);
      io_raw_client->fd = -1;
      io_raw_client->state = IO_RAW_CLIENT_FAILED;
      pbc_grpc_error_unref (error);
    }
  else
    {
      struct sockaddr tmp;
      socklen_t tmplen = sizeof(tmp);
      if (getpeername (fd, &tmp, tmp_len) != 0)
        {
          /* continue waiting */
          if (errno == ENOTCONN)
            return;

          /* report error */
          PBC_GRPC_Error *error;
          error = pbc_grpc_error_new_printf ("verifying socket is connected: %s",
                                             strerror (errno));
          if (io_raw_client->error == NULL)
            fprintf(stderr, "unhandled connecting error: %s\n", error->message);
          else
            io_raw_client->error (error, io_raw_client->callback_data);
          pbc_grpc_dispatch_close_fd (io_raw_client->dispatch, fd);
          io_raw_client->fd = -1;
          io_raw_client->state = IO_RAW_CLIENT_FAILED;
          pbc_grpc_error_unref (error);
        }

      io_raw_client->state = IO_RAW_CLIENT_IS_CONNECTED;

    int events = 0;
    if (io_rc->readable != NULL)
      events |= PBC_GRPC_EVENT_READABLE;
    if (io_rc->writable != NULL)
      events |= PBC_GRPC_EVENT_WRITABLE;
    pbc_grpc_dispatch_watch_fd (io_raw_client->dispatch,
                                io_raw_client->fd,
                                events,
                                handle_io_raw_client_events,
                                io_rc);
  }
}

static PBC_GRPC_IO *
raw_new_client     (PBC_GRPC_IOSystem *system,
                    PBC_GRPC_IO_ClientOptions *options,
                    PBC_GRPC_Error **error)
{
  DispatchBasedIOSystem *dsystem = (DispatchBasedIOSystem *) system;
  IORawClient *rv = ...;
  rv->base_io.io_class = &pbc_grpc_io_raw_client_class;
  rv->port = options->port;

  rv->state = IO_RAW_CLIENT_INIT;
  rv->fd = -1;
  rv->dispatch = dsystem->dispatch;
  rv->readable = rv->writable = NULL;
  rv->port = options->port;
  rv->error = NULL;
  rv->callback_data = NULL;

  if (options->unix_domain_socket != NULL)
    {
      rv->fd = socket (PF_LOCAL, SOCK_STREAM, 0);
      set_nonblocking (rv->fd);
      int connect_rv;
      uint8_t sockaddr_bytes[MAX_SOCKADDR_SIZE_FOR_UNIX];
      socklen_t socklen = make_sockaddr_unix (options->unix_domain_socket, sockaddr_bytes);

retry_unixdomain_connect:
      connect_rv = connect (rv->fd, (struct sockaddr *) sockaddr_bytes, socklen);
      if (connect_rv == 0)
        {
          rv->state = IO_RAW_CLIENT_IS_CONNECTED;
        }
      else if (errno == EINPROGRESS)
        {
          rv->state = IO_RAW_CLIENT_IS_CONNECTING;
          pbc_grpc_dispatch_watch_fd (rv->dispatch, rv->fd,
                                      PBC_GRPC_EVENT_READABLE|PBC_GRPC_EVENT_WRITABLE,
                                      client_handle_is_connecting,
                                      rv);
        }
      else if (errno == EINTR)
        goto retry_unixdomain_connect;
      else
        {
          *error = pbc_grpc_error_new_printf ("error connecting to %s: %s",
                                              options->hostname, strerror (errno));
          close (rv->fd);
          free (rv);
          return NULL;
        }
    }
  else if (options->use_ip_address pbc_grpc_dns_is_numeric (options->hostname, &addr))
    {
      rv->fd = socket (PF_INET, SOCK_STREAM, 0);
      set_nonblocking (rv->fd);
      int connect_rv;
      uint8_t sockaddr_bytes[MAX_SOCKADDR_SIZE_FOR_IP];
      socklen_t socklen = make_sockaddr (addr, rv->port, sockaddr_bytes);

retry_connect:
      connect_rv = connect (rv->fd, (struct sockaddr *) sockaddr_bytes, socklen);
      if (connect_rv == 0)
        {
          rv->state = IO_RAW_CLIENT_IS_CONNECTED;
        }
      else if (errno == EINPROGRESS)
        {
          rv->state = IO_RAW_CLIENT_IS_CONNECTING;
          pbc_grpc_dispatch_watch_fd (rv->dispatch, rv->fd,
                                      PBC_GRPC_EVENT_READABLE|PBC_GRPC_EVENT_WRITABLE,
                                      handle_is_connecting,
                                      rv);
        }
      else if (errno == EINTR)
        goto retry_connect;
      else
        {
          *error = pbc_grpc_error_new_printf ("error connecting to %s: %s",
                                              options->hostname, strerror (errno));
          close (rv->fd);
          free (rv);
          return NULL;
        }
    }
  else
    {
      PBC_GRPC_Error *err = NULL;
      rv->error = handle_error_during_construction;
      rv->callback_data = &err;
      rv->state = IO_RAW_CLIENT_DOING_NAME_LOOKUP;
      pbc_grpc_dns_resolver->resolve (pbc_grpc_dns_resolver,
                                      rv->dispatch,
                                      options->hostname,
                                      handle_dns_resolved,
                                      rv);
      rv->error = NULL;
      rv->callback_data = NULL;
      if (err != NULL)
        {
          *error = err;
          free (rv);
          return NULL;
        }
    }
  return &rv->base_io;
}

 
/* --- Dispatch-Based Raw Server --- */
/*
 *  ----------------------------
 * --------- Raw Server ---------
 *  ----------------------------
 */

static PBC_GRPC_IO_Listener *
raw_new_server         (PBC_GRPC_IOSystem *system,
                        PBC_GRPC_IO_ServerOptions *options,
                        PBC_GRPC_Error **error)
{
}

/* --- Dispatch-Based OpenSSL-based SSL Client --- */
/*
 *  ----------------------------
 * --------- SSL Client ---------
 *  ----------------------------
 */


static BIO_METHOD *
bio_method_new_pbc_grpc_io (void)
{
  static BIO_METHOD *rv = NULL;
  if (rv == NULL)
    {
      BIO_METHOD *bm = BIO_meth_new (10000, "PBC_GRPC_IO_Client");
      BIO_meth_set_write (bm, handle_client_bio_write);
      BIO_meth_set_read (bm, handle_client_bio_write);
      BIO_meth_set_ctrl (bm, handle_client_bio_ctrl);
      BIO_meth_set_destroy (bm, handle_client_bio_destroy);
      rv = bm;
    }
  return rv;
}
typedef struct IOSSLClient IOSSLClient;
struct IOSSLClient
{
  PBC_GRPC_IO base_io;
  SSL *ssl;
  BIO *bio;
  PBC_GRPC_IO *underlying;
};

static PBC_GRPC_IO_Class pbc_grpc_io_ssl_client_class =
{
  "SSLClient",
  io_ssl_client_set_wants,
  io_ssl_client_read,
  io_ssl_client_write,
  io_ssl_client_destroy,
  io_ssl_client_status_as_string
};

static PBC_GRPC_IO *
io_openssl_new_ssl_client (PBC_GRPC_IOSystem *system,
                           PBC_GRPC_IO_SSLClientOptions *options,
                           PBC_GRPC_Error **error);
{
  PBC_GRPC_IO *underlying = options->underlying_io;
  ... parse URL
  if (underlying == NULL)
    {
      PBC_GRPC_IO_ClientOptions underying_options;
      ...
      underlying = raw_new_client (system, &underlying_client_options,
    }

  DispatchBasedIOSystem *dsystem = (DispatchBasedIOSystem *) system;
  IOSSLClient *rv = NEW (IO_SSL_Client);
  rv->base_io.io_class = &pbc_grpc_io_raw_client_class;

  BIO *bio = BIO_new (bio_method_new_pbc_grpc_io ());
  bio->ptr = rv;
  bio->init = 1;
  rv->base_io.io_class = &pbc_grpc_io_ssl_client_class;
  rv->bio = bio;
  SSL_CTX *ctx = SSL_CTX_new (...);
  SSL *ssl = SSL_new (ctx);
  rv->ssl = ssl;
  rv->underlying = underlying;
  SSL_set_bio(ssl, bio, bio);
  SSL_set_connect_state(ssl);
  return &rv->base_io;
}


static PBC_GRPC_IO_Listener *
io_openssl_new_ssl_server        (PBC_GRPC_IOSystem *system,
                                  PBC_GRPC_IO_SSLServerOptions *options,
                                  PBC_GRPC_Error **error);

static PBC_GRPC_IO_Timer *
io_openssl_new_timer             (PBC_GRPC_IOSystem    *system,
                                  uint64_t              microseconds,
                                  PBC_GRPC_IO_TimerFunc func,
                                  void                 *func_data);

DispatchBasedIOSystem dispatch_based_io_system =
{
  { raw_new_client,
    raw_new_server,
    raw_new_ssl_client,
    raw_new_ssl_server,
    raw_new_timer
  },
  pbc_grpc_io_system
};

PBC_GRPC_IOSystem * pbc_grpc_io_system = (PBC_GRPC_IOSystem*) &dispatch_based_io_system;


PBC_GRPC_IOSystem * pbc_grpc_io_system_new_from_dispatch (PBC_GRPC_Dispatch *);



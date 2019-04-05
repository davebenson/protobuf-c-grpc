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
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

PBC_GRPC_IO *
pbc_grpc_io_system_new_client        (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_ClientOptions *options,
                                      PBC_GRPC_Error **error)
{
  return system->new_client(system, options, error);
}
PBC_GRPC_IO_Listener *
pbc_grpc_io_system_new_server        (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_ServerOptions *options,
                                      PBC_GRPC_Error **error)
{
  return system->new_server(system, options, error);
}

PBC_GRPC_IO_SSLContext *
pbc_grpc_io_system_new_ssl_context   (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLContextOptions *options,
                                      PBC_GRPC_Error **error)
{
  return system->new_ssl_context(system, options, error);
}

PBC_GRPC_IO *
pbc_grpc_io_system_new_ssl_client    (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLClientOptions *options,
                                      PBC_GRPC_Error **error)
{
  return system->new_ssl_client(system, options, error);
}
PBC_GRPC_IO_Listener *
pbc_grpc_io_system_new_ssl_server    (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLServerOptions *options,
                                      PBC_GRPC_Error **error)
{
  return system->new_ssl_server(system, options, error);
}

PBC_GRPC_IO_Timer *
pbc_grpc_io_system_new_timer         (PBC_GRPC_IOSystem *system,
                                      uint64_t microseconds,
                                      PBC_GRPC_IO_TimerFunc func,
                                      void                 *timer_data)
{
  return system->new_timer (system, microseconds, func, timer_data);
}

PBC_GRPC_IO      * pbc_grpc_io_ref        (PBC_GRPC_IO    *io)
{
  assert (io->ref_count > 0);
  io->ref_count += 1;
  return io;
}
void               pbc_grpc_io_unref      (PBC_GRPC_IO    *io)
{
  assert (io->ref_count > 0);
  io->ref_count -= 1;
  if (io->ref_count == 0)
    io->io_class->finalize (io);
}

void               pbc_grpc_io_set_wants  (PBC_GRPC_IO    *io,
                                           PBC_GRPC_IOFunc readable,
                                           PBC_GRPC_IOFunc writable,
                                           PBC_GRPC_IOErrorFunc error,
                                           PBC_GRPC_IOFunc destroyed,
                                           void           *callback_data)
{
  assert (io->ref_count > 0);
  io->io_class->set_wants(io, readable, writable, error, destroyed, callback_data);
}

PBC_GRPC_IO_Result pbc_grpc_io_read       (PBC_GRPC_IO    *io,
                                           size_t          size,
                                           uint8_t        *data)
{
  assert (io->ref_count > 0);
  return io->io_class->read (io, size, data);
}
PBC_GRPC_IO_Result pbc_grpc_io_write      (PBC_GRPC_IO    *io,
                                           size_t          size,
                                           const uint8_t  *data)
{
  assert (io->ref_count > 0);
  return io->io_class->write (io, size, data);
}
void               pbc_grpc_io_close      (PBC_GRPC_IO    *io)
{
  assert (io->ref_count > 0);
  return io->io_class->close (io);
}
char *             pbc_grpc_io_status_as_string (PBC_GRPC_IO *io)
{
  if (io->io_class->status_as_string != NULL)
    return io->io_class->status_as_string (io);
  else
    return strdup (io->io_class->class_name);
}


typedef struct {
  PBC_GRPC_IOSystem base_system;
  PBC_GRPC_Dispatch *dispatch;
} DispatchBasedIOSystem;


/* --- Dispatch-Based Raw Client --- */
/*
 *  ----------------------------
 * --------- Raw Client ---------
 *  ----------------------------
 */
typedef struct IORawClient IORawClient;
struct IORawClient
{
  PBC_GRPC_IO          base_io;
  PBC_GRPC_Dispatch   *dispatch;
  int                  fd;
  unsigned             doing_name_lookup : 1;
  unsigned             connecting : 1;
  unsigned             invoked_destroyed : 1;
  unsigned             failed : 1;
  PBC_GRPC_IOFunc      readable;
  PBC_GRPC_IOFunc      writable;
  PBC_GRPC_IOFunc      destroyed;
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
                         PBC_GRPC_IOFunc destroyed,
                         void           *callback_data)
{
  IORawClient *io_rc = (IORawClient *) io;
  io_rc->readable = readable;
  io_rc->writable = writable;
  io_rc->error = error;
  io_rc->destroyed = destroyed;
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

  assert (!io_raw_client->invoked_destroyed);
  assert (!io_raw_client->failed);
  if (io_raw_client->doing_name_lookup
   || io_raw_client->connecting)
    {
      rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
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

  if (io_raw_client->connecting
   || io_raw_client->doing_name_lookup)
    {
      rv.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
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
  else if (write_rv < size)
    {
      rv.code = PBC_GRPC_IO_RESULT_PARTIAL;
      rv.partial.amount = write_rv;
    }
  else
    {
      rv.code = PBC_GRPC_IO_RESULT_SUCCESS;
    }
  return rv;
}

static void
io_raw_client_close   (PBC_GRPC_IO *io)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  assert (!io_raw_client->invoked_destroyed);
  if (io_raw_client->fd >= 0)
    {
      pbc_grpc_dispatch_close_fd (io_raw_client->dispatch, io_raw_client->fd);
      io_raw_client->fd = -1;
    }
  if (io_raw_client->destroyed)
    io_raw_client->destroyed (io, io_raw_client->callback_data);
  io_raw_client->invoked_destroyed = 1;
  if (!io_raw_client->doing_name_lookup)
    {
      free (io);
    }
}

static void
io_raw_client_finalize   (PBC_GRPC_IO *io)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  assert(io->ref_count == 0);
  if (io_raw_client->fd >= 0)
    {
      pbc_grpc_dispatch_close_fd (io_raw_client->dispatch, io_raw_client->fd);
      io_raw_client->fd = -1;
    }
  free(io);
}

static char *
sockaddr_as_string (size_t len, struct sockaddr *addr)
{
  switch (addr->sa_family)
    {
    case AF_UNIX:
      {
        struct sockaddr_un *addr_un = (struct sockaddr_un *) addr;
        const char *path = addr_un->sun_path;
        return pbc_grpc_strdup_printf("unix_domain_socket[%*s]",
                                      (unsigned) sizeof (addr_un->sun_path),
                                      path);
      }
    case AF_INET:
      {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint8_t *ip = (uint8_t *) &(in->sin_addr);
        uint16_t port = ntohs (in->sin_port);
        return pbc_grpc_strdup_printf ("%d.%d.%d.%d:%d",
                                       ip[0], ip[1], ip[2], ip[3], port);
      }
    case AF_INET6:
      {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *)addr;
        const uint16_t *ip = (const uint16_t *) (&in->sin6_addr);
        unsigned max_zeros = 0, max_zeros_start = 8;
        unsigned cur_zeros = 0, cur_zeros_start = 0;
        for (unsigned i = 0; i < 8; i++)
          if (ip[i] == 0)
            {
              if (cur_zeros == 0)
                {
                  cur_zeros = 1;
                  cur_zeros_start = i;
                }
              else
                cur_zeros++;
              if (cur_zeros > max_zeros)
                {
                  max_zeros = cur_zeros;
                  max_zeros_start = cur_zeros_start;
                }
            }
          else
            cur_zeros = 0;

        // we use the value max_zeros_start==8 to trigger the no-abbreviation case.
        if (max_zeros <= 1)
          {
            max_zeros = 0;
            max_zeros_start = 8;
          }
            //   [  xxxx: * 8  ]   :  xxxxx 
        char buf[1   + 8 * 5 + 1 + 1 + 5 + 1];
        unsigned at = 0;
        buf[at++] = '[';
        for (unsigned i = 0; i < max_zeros_start; i++)
          {
            /* print XXXX: */
            at += snprintf(buf + at, 6, "%x:", ntohs(ip[i]));
          }
        for (unsigned i = max_zeros_start + max_zeros; i < 8; i++)
          {
            /* print :XXXX */
            at += snprintf(buf + at, 6, ":%x", ntohs(ip[i]));
          }

        // handle no-abbreviate case, which adds a terminal ':' from the first loop
        if (max_zeros_start == 8)
          at--;         /* remove trailing : */
        buf[at++] = ']';
        buf[at++] = ':';
        at += snprintf (buf + at, 6, "%u", ntohs(in->sin6_port));
        buf[at++] = 0;
        char *rv = malloc (at);
        memcpy (rv, buf, at);
        return rv;
      }
    default:
      assert(0);
      return pbc_grpc_strdup_printf ("unknown-addr-type: 0x%x", addr->sa_family);
    }
}

static char *
io_raw_client_status_as_string (PBC_GRPC_IO    *io)
{
  IORawClient *io_raw_client = (IORawClient *) io;
  struct sockaddr_storage us, them;
  socklen_t us_len = sizeof(us), them_len = sizeof(them);
  char *us_name = NULL, *them_name = NULL;
  if (io_raw_client->fd >= 0)
    {
      getpeername (io_raw_client->fd, (struct sockaddr *) &us, &us_len);
      getsockname (io_raw_client->fd, (struct sockaddr *) &them, &them_len);
      us_name = sockaddr_as_string (us_len, (struct sockaddr *) &us);
      them_name = sockaddr_as_string (them_len, (struct sockaddr *) &them);
    }
  char *rv = NULL;
  if (io_raw_client->doing_name_lookup)
    {
      rv = strdup ("raw-client: doing name-lookup");
    }
  else if (io_raw_client->connecting)
    {
      rv = pbc_grpc_strdup_printf ("raw-client: %s connecting to %s",
                                   us_name, them_name);
    }
  else
    {
      rv = pbc_grpc_strdup_printf ("raw-client: %s connected to %s",
                                   us_name, them_name);
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
  io_raw_client_close,
  io_raw_client_finalize,
  io_raw_client_status_as_string
};

static void
io_raw_client_failed (IORawClient *io_raw_client,
                      PBC_GRPC_Error *take_error)
{
  switch (io_raw_client->state)
    {
    case IO_RAW_CLIENT_DOING_NAME_LOOKUP:
      io_raw_client->error (&io_raw_client->base_io, take_error, io_raw_client->callback_data);
      io_raw_client->state = IO_RAW_CLIENT_DNS_FAILED:
      break;
    case IO_RAW_CLIENT_FAILED:
    case IO_RAW_CLIENT_DNS_FAILED:
      fprintf(stderr, "io_raw_client_failed: multiple failures: %s\n", take_error->message);
      break;
    default:
      io_raw_client->error (&io_raw_client->base_io, take_error, io_raw_client->callback_data);
      io_raw_client->state = IO_RAW_CLIENT_FAILED;
      break;
    }
  pbc_grpc_error_unref (take_error);
}

static void
client_handle_is_connecting (PBC_GRPC_FD   fd,
                             unsigned       events,
                             void          *callback_data)
{
  IORawClient *io_raw_client = (IORawClient *) callback_data;
  int e;
retry_getsockopt:
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &e) != 0)
    {
      if (errno == EINTR)
        goto retry_getsockopt;

      io_raw_client_failed (io_raw_client,
                            pbc_grpc_error_new_printf ("error getsockopt to determine connectedness: %s", strerror (errno)));
      return;
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
      return;
    }

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
  }

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

static PBC_GRPC_IO *
raw_new_client     (PBC_GRPC_IOSystem *system,
                    PBC_GRPC_IO_ClientOptions *options,
                    PBC_GRPC_Error **error)
{
  DispatchBasedIOSystem *dsystem = (DispatchBasedIOSystem *) system;
  IORawClient *rv = NEW (IORawClient);
  rv->base_io.ref_count = 1;
  rv->base_io.io_system = system;
  rv->base_io.io_class = &pbc_grpc_io_raw_client_class;
  rv->base_io.last_error = NULL;
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
  else if (options->use_ip_address
        || pbc_grpc_dns_is_numeric (options->hostname, &addr))
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
typedef struct IORawServer IORawServer;
struct IORawServer
{
  PBC_GRPC_IO          base_io;
  int                  fd;
  unsigned             failed : 1;
  PBC_GRPC_IOFunc      readable;
  PBC_GRPC_IOFunc      writable;
  PBC_GRPC_IOFunc      destroyed;
  PBC_GRPC_IOErrorFunc error;
  void                *callback_data;

};

static IORawServer *
io_raw_server_new (PBC_GRPC_Dispatch *dispatch, int fd)
{
...
}

struct IORawServerListener
{
  PBC_GRPC_IO_Listener base_listener;
  int fd;
  PBC_GRPC_IO_AcceptFunc accept_func;
  void *accept_func_data;
  bool has_watch;
};
static void
io_raw_server_listener_set_handler    (PBC_GRPC_IO_Listener *listener,
                                       PBC_GRPC_IO_AcceptFunc func,
                                       void                  *func_data)
{
  IORawServerListener *lis = (IORawServerListener *) listener;
  DispatchBasedIOSystem *iosys = (DispatchBasedIOSystem *) listener->io_system;
  if (lis->fd < 0)
    {
      return;
    }
  if (lis->has_watch && func == NULL)
    {
      pbc_grpc_dispatch_watch_fd (iosys->dispatch, lis->fd,
                                  PBC_GRPC_EVENT_READABLE,
                                  lis);
      lis->accept_func = NULL;
      lis->accept_func_data = NULL;
      lis->has_watch = false;
    }
  else if (!lis->has_watch && func != NULL)
    {
      pbc_grpc_dispatch_watch_fd (iosys->dispatch, lis->fd,
                                  0,
                                  lis);
      lis->accept_func = func;
      lis->accept_func_data = func_data;
      lis->has_watch = true;
    }
  else if (func != NULL)
    {
      lis->accept_func = func;
      lis->accept_func_data = func_data;
    }
}
static PBC_GRPC_IO_AcceptResult
io_raw_server_listener_accept         (PBC_GRPC_IO_Listener *listener)
{
  IORawServerListener *lis = (IORawServerListener *) listener;
  struct sockaddr_storage addr;
  int fd;
  PBC_GRPC_IO_AcceptResult res;
  if (lis->fd < 0)
    {
      res.code = PBC_GRPC_IO_ACCEPT_RESULT_ERROR;
      res.error = pbc_grpc_error_new ("already closed");
      return res;
    }

retry_accept:
  fd = accept (lis->fd, (struct sockaddr *) &addr, &addr_len);
  if (fd < 0)
    {
      if (errno == EINTR)
        goto retry_accept;
      if (errno == EAGAIN)
        {
          res.code = PBC_GRPC_IO_ACCEPT_RESULT_WOULD_BLOCK;
          return res;
        }
      res.code = PBC_GRPC_IO_ACCEPT_RESULT_ERROR;
      res.error = pbc_grcp_error_new ("failed to accept file-descriptor: %s",
                                      strerror (errno));
      return res;
    }
  DispatchBasedIOSystem *iosys = (DispatchBasedIOSystem *) listener->io_system;
  res.code = PBC_GRPC_IO_ACCEPT_RESULT_SUCCESS;
  res.success.connection = io_raw_server_new (iosys, fd);
  return res;
}
static void
io_raw_server_listener_close          (PBC_GRPC_IO_Listener *listener)
{
  IORawServerListener *lis = (IORawServerListener *) listener;
  if (lis->fd < 0)
    return;
  close (lis->fd);
}
static void
io_raw_server_listener_finalize       (PBC_GRPC_IO_Listener *listener)
{
  IORawServerListener *lis = (IORawServerListener *) listener;
  if (lis->fd >= 0)
    {
      ...
    }
  free (lis);
}

static PBC_GRPC_IO_Listener *
raw_new_server         (PBC_GRPC_IOSystem *system,
                        PBC_GRPC_IO_ServerOptions *options,
                        PBC_GRPC_Error **error)
{
  IORawServerListener *lis = NEW (IORawServerListener);
  lis->base_listener.set_handler = io_raw_server_listener_set_handler;
  lis->base_listener.close = io_raw_server_listener_close;
  lis->base_listener.finalize = io_raw_server_listener_finalize;
  lis->base_listener.io_system = system;
  lis->base_listener.ref_count = 1;
  lis->fd = fd;
  lis->accept_func = NULL;
  lis->accept_func_data = NULL;
  return &base->base_listener;
}

/* --- OpenSSL-based SSL Context --- */
struct SimpleOpensslContext
{
  PBC_GRPC_IO_SSLContext base_ssl_context;
  SSL_CTX *ctx;
};
static PBC_GRPC_IO_SSLContext *
pbc_grpc_io_new_ssl_context      (PBC_GRPC_IOSystem *system,
                                  PBC_GRPC_IO_SSLContextOptions *options,
                                  PBC_GRPC_Error **error)
{
...
}

/* --- Dispatch-Based OpenSSL-based SSL Connection --- */
typedef struct SSL_Connection SSL_Connection;
struct SSL_Connection
{
  PBC_GRPC_IO base_io;

  PBC_GRPC_IO *underlying;
  SimpleOpensslContext *context;
  SSL *ssl;

  unsigned is_client : 1;
  unsigned handshaking : 1;
  unsigned read_needed_to_handshake : 1;
  unsigned write_needed_to_handshake : 1;
  unsigned read_needed_to_write : 1;
  unsigned write_needed_to_read : 1;

  PBC_GRPC_IOFunc read_hook;
  PBC_GRPC_IOFunc write_hook;
  PBC_GRPC_IOErrorFunc error_hook;
  void *hook_data;
};


static int
bio_pbc_grpc_bwrite (BIO *bio, const char *out, int length)
{
  SSL_Connection *conn = (SSL_Connection *) (bio->ptr);
  DskError *error = NULL;
  unsigned n_written;
  BIO_clear_retry_flags (bio);
  PBC_GRPC_IO *underlying = conn->underlying;
  PBC_GRPC_IO_Result result = underlying->io_class->write (underlying, length, out);
  switch (result.code)
    {
    case PBC_GRPC_IO_RESULT_SUCCESS:
      return length;
    case PBC_GRPC_IO_RESULT_PARTIAL:
      return result.partial.amount;
    case PBC_GRPC_IO_RESULT_EOF:
      return 0;
    case PBC_GRPC_IO_RESULT_WOULD_BLOCK:
      BIO_set_retry_write (bio);
      return -1;
    case PBC_GRPC_IO_RESULT_ERROR:
      dsk_octet_stream_set_error (DSK_OCTET_STREAM (stream), error);
      dsk_error_unref (error);
      break;
    }
  errno = EINVAL;                   /* ugh! */
  return -1;
}


static int
bio_pbc_grpc_bread (BIO *bio, char *in, int max_length)
{
  SSL_Connection *conn = bio->ptr;
  DskError *error = NULL;
  unsigned n_read;
  BIO_clear_retry_flags (bio);
  PBC_GRPC_IO *underlying = conn->underlying;
  PBC_GRPC_IO_Result result = underlying->io_class->read (underlying, max_length, in);
  switch (result.code)
    {
    case PBC_GRPC_IO_RESULT_SUCCESS:
      return max_length;
    case PBC_GRPC_IO_RESULT_PARTIAL:
      return result.partial.amount;
    case PBC_GRPC_IO_RESULT_EOF:
      return 0;
    case PBC_GRPC_IO_RESULT_WOULD_BLOCK:
      BIO_set_retry_read (bio);
      return -1;
    case PBC_GRPC_IO_RESULT_ERROR:
      dsk_octet_stream_set_error (DSK_OCTET_STREAM (stream), error);
      dsk_error_unref (error);
      break;
    }

  errno = EINVAL;                   /* ugh! */
  return -1;

}

static long
bio_pbc_grpc_ctrl (BIO  *bio,
                   int   cmd,
                   long  num,
                   void *ptr)
{
  //SSL_Connection *conn = bio->ptr;
  (void) bio;
  (void) num;
  (void) ptr;

  //DEBUG_BIO("bio_dsk_ctrl: called with cmd=%d", cmd);

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
  (void *) bio;
  // DEBUG_BIO("bio_dsk_create (%p)", bio);
  return 1;
}

static int
bio_pbc_grpc_destroy (BIO *bio)
{
  (void *) bio;
  //DEBUG_BIO("bio_dsk_destroy (%p)", bio);
  return 1;
}



static BIO_METHOD bio_method__ssl_underlying_stream =
{
  22,                   /* type:  this is quite a hack */
  "PBC_GRPC-BIO-Underlying", /* name */
  bio_pbc_grpc_bwrite,       /* bwrite */
  bio_pbc_grpc_bread,        /* bread */
  NULL,                 /* bputs */
  NULL,                 /* bgets */
  bio_pbc_grpc_ctrl,         /* ctrl */
  bio_pbc_grpc_create,       /* create */
  bio_pbc_grpc_destroy,      /* destroy */
  NULL                  /* callback_ctrl */
};
static bool do_handshake (SSL_Connection *conn, PBC_GRPC_Error **error);
static void
io_ssl_connection_set_wants  (PBC_GRPC_IO    *io,
                              PBC_GRPC_IOFunc readable,
                              PBC_GRPC_IOFunc writable,
                              PBC_GRPC_IOErrorFunc error,
                              void           *callback_data);
static PBC_GRPC_IO_Result
io_ssl_connection_read       (PBC_GRPC_IO    *io,
                              size_t          size,
                              uint8_t        *data);
static PBC_GRPC_IO_Result
io_ssl_connection_write      (PBC_GRPC_IO    *io,
                              size_t          size,
                              const uint8_t  *data);
static void
io_ssl_connection_destroy    (PBC_GRPC_IO *io);
static char *
io_ssl_connection_status_as_string (PBC_GRPC_IO    *io);

static PBC_GRPC_IO_Class ssl_connection_class =
{
  "SSLConnection",
  io_ssl_connection_set_wants,
  io_ssl_connection_read,
  io_ssl_connection_write,
  io_ssl_connection_destroy,
  io_ssl_connection_status_as_string
};

static void
io_ssl_connection_set_wants  (PBC_GRPC_IO    *io,
                              PBC_GRPC_IOFunc readable,
                              PBC_GRPC_IOFunc writable,
                              PBC_GRPC_IOErrorFunc error,
                              void           *callback_data)
{
  SSL_Connection *conn = (SSL_Connection *) io;
  assert(io->io_class == &ssl_connection_class);
  conn->read_hook = readable;
  conn->write_hook = writable;
  conn->error_hook = error_hook;
  conn->hook_data = callback_data;
  if (!conn->handshaking)
    ssl_connection_update_wants (conn);
}
static PBC_GRPC_IO_Result
io_ssl_connection_read       (PBC_GRPC_IO    *io,
                              size_t          size,
                              uint8_t        *data)
{
  SSL_Connection *conn = (SSL_Connection *) io;
  PBC_GRPC_IO_Result res;
  if (conn->handshaking)
    {
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    }
  int rv = SSL_read (conn->ssl, data, size);
  if (rv > 0 && rv == size)
    {
      res.code = PBC_GRPC_IO_RESULT_SUCCESS;
      return res;
    }
  else if (rv > 0)
    {
      res.code = PBC_GRPC_IO_RESULT_PARTIAL;
      res.partial.amount = rv;
      return res;
    }
  else if (rv == 0)
    {
      //dsk_set_error (error, "connection closed");
      res.code = PBC_GRPC_IO_RESULT_EOF;
      return res;
    }
  conn->write_needed_to_read = 0;
  switch (SSL_get_error (conn->ssl, rv))
    {
    case SSL_ERROR_WANT_READ:
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    case SSL_ERROR_WANT_WRITE:
      conn->write_needed_to_read = 1;
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    case SSL_ERROR_SYSCALL:
      res.code = PBC_GRPC_IO_RESULT_ERROR;
      res.error = pbc_grpc_error_new ("PBC-GRPC-BIO interface had problems reading");
      return res;
    case SSL_ERROR_NONE:
      res.code = PBC_GRPC_IO_RESULT_ERROR;
      res.error = pbc_grpc_error_new ("error reading from ssl stream, but error code set to none");
      return res;
    default:
      {
        unsigned long l;
        l = ERR_peek_error();
        res.code = PBC_GRPC_IO_RESULT_ERROR;
        res.error = pbc_grpc_error_new_printf (
                       "error reading from ssl stream [in the '%s' library]: %s: %s [is-client=%d]",
                       ERR_lib_error_string(l),
                       ERR_func_error_string(l),
                       ERR_reason_error_string(l),
                       conn->is_client);
        return res;
      }
    }
  return DSK_IO_RESULT_ERROR;
}
static PBC_GRPC_IO_Result
io_ssl_connection_write      (PBC_GRPC_IO    *io,
                              size_t          size,
                              const uint8_t  *data)
{
  SSL_Connection *conn = (SSL_Connection *) io;
  PBC_GRPC_IO_Result res;
  if (conn->handshaking)
    {
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    }
  int rv = SSL_write (conn->ssl, data, size);
  if (rv > 0 && rv == size)
    {
      res.code = PBC_GRPC_IO_RESULT_SUCCESS;
      return res;
    }
  else if (rv > 0)
    {
      res.code = PBC_GRPC_IO_RESULT_PARTIAL;
      res.partial.amount = rv;
      return res;
    }
  else if (rv == 0)
    {
      //dsk_set_error (error, "connection closed");
      res.code = PBC_GRPC_IO_RESULT_EOF;
      return res;
    }
  conn->write_needed_to_read = 0;
  switch (SSL_get_error (conn->ssl, rv))
    {
    case SSL_ERROR_WANT_READ:
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    case SSL_ERROR_WANT_WRITE:
      conn->write_needed_to_read = 1;
      res.code = PBC_GRPC_IO_RESULT_WOULD_BLOCK;
      return res;
    case SSL_ERROR_SYSCALL:
      res.code = PBC_GRPC_IO_RESULT_ERROR;
      res.error = pbc_grpc_error_new ("PBC-GRPC-BIO interface had problems writing");
      return res;
    case SSL_ERROR_NONE:
      res.code = PBC_GRPC_IO_RESULT_ERROR;
      res.error = pbc_grpc_error_new ("error writing to ssl stream, but error code set to none");
      return res;
    default:
      {
        unsigned long l;
        l = ERR_peek_error();
        res.code = PBC_GRPC_IO_RESULT_ERROR;
        res.error = pbc_grpc_error_new_printf (
                       "error writing to ssl stream [in the '%s' library]: %s: %s [is-client=%d]",
                       ERR_lib_error_string(l),
                       ERR_func_error_string(l),
                       ERR_reason_error_string(l),
                       conn->is_client);
        return res;
      }
    }
}
static void
io_ssl_connection_destroy    (PBC_GRPC_IO *io)
{
  SSL_Connection *conn = (SSL_Connection *) io;
  ...
}


  // optional functions
static char *
io_ssl_connection_status_as_string (PBC_GRPC_IO    *io)
{
...
}

static void
ssl_connection_update_wants (SSL_Connection *conn)
{
  bool wants_read, wants_write;
  if (conn->handshaking)
    {
      wants_read = conn->read_needed_to_handshake;
      wants_write = conn->write_needed_to_handshake;
    }
  else
    {
      bool rh = conn->read_hook != NULL;
      bool wh = conn->write_hook != NULL;
      bool r2w = conn->read_needed_to_write;
      bool w2r = conn->write_needed_to_read;
      wants_read = (rh && !w2r) || (wh && r2w);
      wants_write = (wh && !r2w) || (rh && w2r);
   }

  PBC_GRPC_IOFunc r = wants_read ? ssl_connection_handle_underlying_readable : NULL;
  PBC_GRPC_IOFunc w = wants_write ? ssl_connection_handle_underlying_writable : NULL;
  underlying->io_class->set_wants (underlying,
                                   r, w, ssl_connection_handle_underlying_error,
                                   rv);
}
static bool
do_handshake (SSL_Connection *conn, PBC_GRPC_Error **error)
{
  int rv;
  PBC_GRPC_IO *underlying = conn->underlying;
  //DEBUG (stream_ssl, ("do_handshake[client=%u]: start", stream_ssl->is_client));
  assert (conn->handshaking);
  rv = SSL_do_handshake (stream_ssl->ssl);
  if (rv <= 0)
    {
      int error_code = SSL_get_error (stream_ssl->ssl, rv);
      unsigned long l = ERR_peek_error();
      switch (error_code)
        {
        case SSL_ERROR_NONE:
          conn->handshaking = 0;
          break;
        case SSL_ERROR_SYSCALL:
          dsk_set_error (error, "error with underlying stream");
          return false;

        case SSL_ERROR_WANT_READ:
          conn->read_needed_to_handshake = 1;
          conn->write_needed_to_handshake = 0;
          break;
        case SSL_ERROR_WANT_WRITE:
          conn->read_needed_to_handshake = 0;
          conn->write_needed_to_handshake = 1;
          break;
        default:
          {
            dsk_set_error (error,
                         "error doing-handshake on SSL socket: %s: %s [code=%08lx (%lu)] [rv=%d]",
                         ERR_func_error_string(l),
                         ERR_reason_error_string(l),
                         l, l, error_code);
            return false;
          }
        }
    }
  else
    {
      stream_ssl->handshaking = 0;
      dsk_ssl_stream_update_traps (stream_ssl);
    }
  ssl_connection_update_wants (conn);
  return true;
}

static SSL_Connection *
ssl_connection_new (PBC_GRPC_IO *underlying,
                    bool         is_client,
                    SimpleOpensslContext *context,
                    PBC_GRPC_ERROR **error)
{
  SSL_Connection *rv = NEW (SSL_Connection);
  rv->base_io.io_class = &ssl_connection_class;
  rv->base_io.io_system = underlying->io_system;
  rv->ssl = SSL_new (context->ctx);
  rv->is_client = is_client;
  rv->handshaking = 1;
  rv->read_needed_to_handshake = 0;
  rv->write_needed_to_handshake = 0;
  rv->read_needed_to_write = 0;
  rv->write_needed_to_read = 0;
  rv->underlying = underlying;
  
  if (is_client)
    SSL_set_connect_state (rv->ssl);
  else
    SSL_set_accept_state (rv->ssl);
   
  if (!do_handshake (rv, error))
    {
      SSL_free (rv->ssl);
      free (rv);
      return NULL;
    }
  return rv;
}


/* --- Dispatch-Based OpenSSL-based SSL Client --- */
/*
 *  ----------------------------
 * --------- SSL Client ---------
 *  ----------------------------
 */


static PBC_GRPC_IO *
io_openssl_new_ssl_client (PBC_GRPC_IOSystem *system,
                           PBC_GRPC_IO_SSLClientOptions *options,
                           PBC_GRPC_Error **error);
{
  PBC_GRPC_IO *underlying = options->underlying_io;
  ... parse URL
  if (underlying == NULL)
    {
      PBC_GRPC_IO_ClientOptions underlying_options;
      ...
      underlying = raw_new_client (system, &underlying_client_options,
    }
  else
    { 
      assert (system == underlying->io_system);
    }

  PBC_GRPC_IO_SSLContext *context = options->ssl_context;
  SimpleOpensslContext *simple_ssl_ctx = (SimpleOpensslContext *) context;
  SSL_Connection *rv = ssl_connection_new (underlying, true, simple_ssl_ctx, error);
  if (rv == NULL)
    return NULL;
  return &rv->base_io;
}

/* --- Dispatch-Based OpenSSL-based SSL Server --- */
/*
 *  ----------------------------
 * --------- SSL Server ---------
 *  ----------------------------
 */


static PBC_GRPC_IO_Listener *
io_openssl_new_ssl_server        (PBC_GRPC_IOSystem *system,
                                  PBC_GRPC_IO_SSLServerOptions *options,
                                  PBC_GRPC_Error **error);

/* --- Dispatch-Based Timer --- */
typedef struct IOTimer IOTimer;
struct IOTimer
{
  PBC_GRPC_IO_Timer base_timer;
  PBC_GRPC_DispatchTimer *timer;
  DispatchBasedIOSystem *dsystem;
  PBC_GRPC_IO_TimerFunc func;
  void *func_data;
};

static void
timer_cancel (PBC_GRPC_IO_Timer *t)
{
  IOTimer *iotimer = (IOTimer) t;
  pbc_grpc_dispatch_remove_timer (iotimer->dsystem->dispatch,
                                  iotimer->timer);
}
static void
timer_cancel_in_timer (PBC_GRPC_IO_Timer *t)
{
  (void) t;
}

static void
handle_timer_done (PBC_GRPC_Dispatch *dispatch,
                   void              *func_data)
{
  IOTimer *t = func_data;
  assert ((PBC_GRPC_Dispatch *) t->dispatch == dispatch);
  assert (t->cancel == timer_cancel);
  t->cancel = timer_cancel_in_timer;
  t->func (&t->base_timer, t->func_data);
}

static PBC_GRPC_IO_Timer *
io_openssl_new_timer             (PBC_GRPC_IOSystem    *system,
                                  uint64_t              microseconds,
                                  PBC_GRPC_IO_TimerFunc func,
                                  void                 *func_data)
{
  DispatchBasedIOSystem *dsystem = (DispatchBasedIOSystem *) system;
  IOTimer *t = NEW (IOTimer);
  t->base_timer.cancel = timer_cancel;
  t->func = func;
  t->func_data = func_data;
  // TODO: fix resolution!!!
  t->timer = pbc_grpc_dispatch_add_timer_millis (dsystem->dispatch,
                                                 microseconds / 1000 + 1,
                                                 handle_timer_done,
                                                 t);
}

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



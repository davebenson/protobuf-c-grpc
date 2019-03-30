/*
 * PBC_GRPC_IO:  A bi-directional data stream.
 *
 * Because HTTP and SSL do not allow partial shutdown,
 * we also do not allow partial shutdown.
 */

typedef struct {
  PBC_GRPC_IOSystem base_system;
  PBC_GRPC_Dispatch *dispatch;
} DispatchBasedIOSystem;


/* --- Dispatch-Based Raw Client --- */
typedef enum
{
  IO_RAW_CLIENT_DOING_NAME_LOOKUP,
  IO_RAW_CLIENT_IS_CONNECTING,
  IO_RAW_CLIENT_IS_CONNECTED,
  IO_RAW_CLIENT_FAILED,
  IO_RAW_CLIENT_DESTROYED
} IORawClientState;

typedef struct IORawClient IORawClient;
struct IORawClient
{
  PBC_GRPC_IO          base_io;
  IORawClientState     state;
  int                  fd;
  PBC_GRPC_IOFunc      readable;
  PBC_GRPC_IOFunc      writable;
  PBC_GRPC_IOErrorFunc error;
  void                *callback_data;
};

static void
io_raw_client_set_wants (PBC_GRPC_IO    *io,
                         PBC_GRPC_IOFunc readable,
                         PBC_GRPC_IOFunc writable,
                         PBC_GRPC_IOErrorFunc error,
                         void           *callback_data)
{
...
}

static PBC_GRPC_IO_Result
io_raw_client_read      (PBC_GRPC_IO    *io,
                         size_t          size,
                         uint8_t        *data)
{
...
}

static PBC_GRPC_IO_Result
io_raw_client_write     (PBC_GRPC_IO    *io,
                         size_t          size,
                         const uint8_t  *data)
{
...
}

static void
io_raw_client_destroy   (PBC_GRPC_IO *io)
{
...
}

static char *
io_raw_client_status_as_string (PBC_GRPC_IO    *io)
{
...
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

static PBC_GRPC_IO *
raw_new_client     (PBC_GRPC_IOSystem *system,
                    PBC_GRPC_IO_ClientOptions *options,
                    PBC_GRPC_Error **error)
{
  DispatchBasedIOSystem *dsystem = (DispatchBasedIOSystem *) system;
  IORawClient *rv = ...;
  rv->base_io.io_class = &pbc_grpc_io_raw_client_class;
  ...
  rv->state = ...
  rv->fd = -1;
  rv->readable = rv->writable = NULL;
  rv->error = NULL;
  rv->callback_data = NULL;
  return &rv->base_io;
}

 
/* --- Dispatch-Based Raw Server --- */

static PBC_GRPC_IO_Listener *
raw_new_server         (PBC_GRPC_IOSystem *system,
                        PBC_GRPC_IO_ServerOptions *options,
                        PBC_GRPC_Error **error)
{
}

/* --- Dispatch-Based OpenSSL-based SSL Client --- */

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
      raw_new_client (system, &underlying_client_options,
    }
              
  PBC_GRPC_IO_Listener *
               (*new_ssl_server)       (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_SSLServerOptions *options,
                                        PBC_GRPC_Error **error);
  
  PBC_GRPC_IO_Timer *(*new_timer)      (PBC_GRPC_IOSystem *system,
                                        uint64_t microseconds,
                                        PBC_GRPC_IO_TimerFunc func,
                                        void                 *func_data);
};

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


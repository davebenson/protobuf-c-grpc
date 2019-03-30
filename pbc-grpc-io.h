/*
 * PBC_GRPC_IO:  A bi-directional data stream.
 *
 * Because HTTP and SSL do not allow partial shutdown,
 * we also do not allow partial shutdown.
 */

typedef enum
{
  PBC_GRPC_IO_RESULT_SUCCESS,
  PBC_GRPC_IO_RESULT_PARTIAL,
  PBC_GRPC_IO_RESULT_AGAIN,
  PBC_GRPC_IO_RESULT_CLOSED,
  PBC_GRPC_IO_RESULT_ERROR
} PBC_GRPC_IO_ResultCode;

typedef struct {
  PBC_GRPC_IO_ResultCode code;
  union {
    struct { size_t amount; } partial;
    PBC_GRPC_Error *error;
  };
} PBC_GRPC_IO_Result;


typedef struct PBC_GRPC_IO PBC_GRPC_IO;
typedef struct PBC_GRPC_IO_Class PBC_GRPC_IO_Class;

typedef void (*PBC_GRPC_IOFunc)(PBC_GRPC_IO *io, void *callback_data);

struct PBC_GRPC_IO_Class
{
  const char          *class_name;
  void               (*set_wants) (PBC_GRPC_IO    *io,
                                   PBC_GRPC_IOFunc readable,
                                   PBC_GRPC_IOFunc writable,
                                   PBC_GRPC_IOErrorFunc error,
                                   void           *callback_data);
  PBC_GRPC_IO_Result (*read)      (PBC_GRPC_IO    *io,
                                   size_t          size,
                                   uint8_t        *data);
  PBC_GRPC_IO_Result (*write)     (PBC_GRPC_IO    *io,
                                   size_t          size,
                                   const uint8_t  *data);
  void               (*destroy)   (PBC_GRPC_IO *io);


  // optional functions
  char *(*status_as_string) (PBC_GRPC_IO    *io);
};
 
struct PBC_GRPC_IO
{
  PBC_GRPC_IO_Class *io_class;
};

struct PBC_GRPC_IO_Listener
{
  void (*set_backlog_size) (PBC_GRPC_IO_Listener *,
                            int backlog_size);
  void (*set_handler)      (PBC_GRPC_IO_Listener *,
                            PBC_GRPC_IO_AcceptFunc func,
                            void *func_data);
  void (*destroy)          (PBC_GRPC_IO_Listener *listener);
};

struct PBC_GRPC_IO_Timer
{
  void (*cancel)(PBC_GRPC_IO_Timer *timer);
};

struct PBC_GRPC_IOSystem
{
  PBC_GRPC_IO *(*new_client)           (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_ClientOptions *options,
                                        PBC_GRPC_Error **error);
  PBC_GRPC_IO_Listener *
               (*new_server)           (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_ServerOptions *options,
                                        PBC_GRPC_Error **error);

  PBC_GRPC_IO *(*new_ssl_client)       (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_SSLClientOptions *options,
                                        PBC_GRPC_Error **error);
  PBC_GRPC_IO_Listener *
               (*new_ssl_server)       (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_SSLServerOptions *options,
                                        PBC_GRPC_Error **error);
  
  PBC_GRPC_IO_Timer *(*new_timer)      (PBC_GRPC_IOSystem *system,
                                        uint64_t microseconds,
                                        PBC_GRPC_IO_TimerFunc func,
                                        void                 *func_data);
};

extern PBC_GRPC_IOSystem * pbc_grpc_io_system;

PBC_GRPC_IOSystem * pbc_grpc_io_system_new_from_dispatch (PBC_GRPC_Dispatch *);


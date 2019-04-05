/*
 * PBC_GRPC_IO:  A bi-directional data stream.
 *
 * Because HTTP and SSL do not allow partial shutdown,
 * we also do not allow partial shutdown.
 */

#include "pbc-grpc-common.h"
#include "pbc-grpc-dispatch.h"

typedef enum
{
  PBC_GRPC_IO_RESULT_SUCCESS,
  PBC_GRPC_IO_RESULT_PARTIAL,
  PBC_GRPC_IO_RESULT_WOULD_BLOCK,
  PBC_GRPC_IO_RESULT_EOF,
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
typedef struct PBC_GRPC_IO_Listener PBC_GRPC_IO_Listener;
typedef struct PBC_GRPC_IO_Timer PBC_GRPC_IO_Timer;
typedef struct PBC_GRPC_IO_SSLContext PBC_GRPC_IO_SSLContext;
typedef struct PBC_GRPC_IOSystem PBC_GRPC_IOSystem;

typedef void (*PBC_GRPC_IOFunc)(PBC_GRPC_IO *io, void *callback_data);
typedef void (*PBC_GRPC_IOErrorFunc)(PBC_GRPC_IO *io, PBC_GRPC_Error *error, void *callback_data);

struct PBC_GRPC_IO_Class
{
  const char          *class_name;
  void               (*set_wants) (PBC_GRPC_IO    *io,
                                   PBC_GRPC_IOFunc readable,
                                   PBC_GRPC_IOFunc writable,
                                   PBC_GRPC_IOErrorFunc error,
                                   PBC_GRPC_IOFunc destroyed,
                                   void           *callback_data);
  PBC_GRPC_IO_Result (*read)      (PBC_GRPC_IO    *io,
                                   size_t          size,
                                   uint8_t        *data);
  PBC_GRPC_IO_Result (*write)     (PBC_GRPC_IO    *io,
                                   size_t          size,
                                   const uint8_t  *data);
  void               (*close)     (PBC_GRPC_IO *io);

  /* This should NOT be called directly; instead use pbc_grpc_io_unref() */
  void               (*finalize)  (PBC_GRPC_IO *io);


  // optional functions
  char *(*status_as_string) (PBC_GRPC_IO    *io);
};
 
struct PBC_GRPC_IO
{
  PBC_GRPC_IO_Class *io_class;
  PBC_GRPC_IOSystem *io_system;
  unsigned ref_count;
  PBC_GRPC_Error *last_error;
};

PBC_GRPC_IO      * pbc_grpc_io_ref        (PBC_GRPC_IO    *io);
void               pbc_grpc_io_unref      (PBC_GRPC_IO    *io);
void               pbc_grpc_io_set_wants  (PBC_GRPC_IO    *io,
                                           PBC_GRPC_IOFunc readable,
                                           PBC_GRPC_IOFunc writable,
                                           PBC_GRPC_IOErrorFunc error,
                                           PBC_GRPC_IOFunc destroyed,
                                           void           *callback_data);
PBC_GRPC_IO_Result pbc_grpc_io_read       (PBC_GRPC_IO    *io,
                                           size_t          size,
                                           uint8_t        *data);
PBC_GRPC_IO_Result pbc_grpc_io_write      (PBC_GRPC_IO    *io,
                                           size_t          size,
                                           const uint8_t  *data);
void               pbc_grpc_io_close      (PBC_GRPC_IO    *io);
char *             pbc_grpc_io_status_as_string (PBC_GRPC_IO *io);


typedef void (*PBC_GRPC_IO_AcceptFunc) (PBC_GRPC_IO_Listener *listener,
                                        void                 *func_data);
          
typedef enum
{
  PBC_GRPC_IO_ACCEPT_RESULT_SUCCESS,
  PBC_GRPC_IO_ACCEPT_RESULT_WOULD_BLOCK,
  PBC_GRPC_IO_ACCEPT_RESULT_ERROR
} PBC_GRPC_IO_AcceptResultCode;
typedef struct PBC_GRPC_IO_AcceptResult PBC_GRPC_IO_AcceptResult;
struct PBC_GRPC_IO_AcceptResult
{
  PBC_GRPC_IO_AcceptResultCode code;
  union {
    struct {
      PBC_GRPC_IO *connection;
    } success;
    PBC_GRPC_Error *error;
  };
};


  
                  

struct PBC_GRPC_IO_Listener
{
  void (*set_handler)      (PBC_GRPC_IO_Listener *,
                            PBC_GRPC_IO_AcceptFunc func,
                            void *func_data);
  PBC_GRPC_IO_AcceptResult
       (*accept)           (PBC_GRPC_IO_Listener *);
  void (*close)            (PBC_GRPC_IO_Listener *listener);
  void (*finalize)         (PBC_GRPC_IO_Listener *listener);
  PBC_GRPC_IOSystem *io_system;
  unsigned ref_count;
};
void pbc_grpc_io_listener_set_handler(PBC_GRPC_IO_Listener *listener,
                                      PBC_GRPC_IO_AcceptFunc func,
                                      void *func_data);
PBC_GRPC_IO_AcceptResult
     pbc_grpc_io_listener_accept     (PBC_GRPC_IO_Listener *listener);
void pbc_grpc_io_listener_close      (PBC_GRPC_IO_Listener *listener);
void pbc_grpc_io_listener_finalize   (PBC_GRPC_IO_Listener *listener);

typedef void (*PBC_GRPC_IO_TimerFunc)(void *timer_data);
struct PBC_GRPC_IO_Timer
{
  void (*cancel)(PBC_GRPC_IO_Timer *timer);
};

struct PBC_GRPC_IO_SSLContext
{
  PBC_GRPC_IOSystem *io_system;
};

/*
 * Options to provide to create a new client connection (unencrypted)
 */
typedef struct {
  /* Connecting to IP addresses, either directly or via DNS. */
  const char *hostname;
  bool use_ip_address;
  PBC_GRPC_IPAddress ip_address;
  int port;

  const char *unix_domain_socket;
} PBC_GRPC_IO_ClientOptions;

typedef struct {
  int port;
  int backlog_length;
  const char *unix_domain_socket;
} PBC_GRPC_IO_ServerOptions;

typedef struct {
  const char     *cert_filename;
  const char     *key_filename;
  const char     *password;
} PBC_GRPC_IO_SSLContextOptions;

typedef struct {
  PBC_GRPC_IO_ClientOptions raw;
  PBC_GRPC_IO_SSLContext *ssl_context;
} PBC_GRPC_IO_SSLClientOptions;

typedef struct {
  PBC_GRPC_IO_ServerOptions raw;
  PBC_GRPC_IO_SSLContext *ssl_context;
} PBC_GRPC_IO_SSLServerOptions;

struct PBC_GRPC_IOSystem
{
  PBC_GRPC_IO *(*new_client)           (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_ClientOptions *options,
                                        PBC_GRPC_Error **error);
  PBC_GRPC_IO_Listener *
               (*new_server)           (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_ServerOptions *options,
                                        PBC_GRPC_Error **error);

  PBC_GRPC_IO_SSLContext *
               (*new_ssl_context)      (PBC_GRPC_IOSystem *system,
                                        PBC_GRPC_IO_SSLContextOptions *options,
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
                                        void                 *timer_data);
};


PBC_GRPC_IO *
pbc_grpc_io_system_new_client        (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_ClientOptions *options,
                                      PBC_GRPC_Error **error);
PBC_GRPC_IO_Listener *
pbc_grpc_io_system_new_server        (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_ServerOptions *options,
                                      PBC_GRPC_Error **error);

PBC_GRPC_IO_SSLContext *
pbc_grpc_io_system_new_ssl_context   (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLContextOptions *options,
                                      PBC_GRPC_Error **error);

PBC_GRPC_IO *
pbc_grpc_io_system_new_ssl_client    (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLClientOptions *options,
                                      PBC_GRPC_Error **error);
PBC_GRPC_IO_Listener *
pbc_grpc_io_system_new_ssl_server    (PBC_GRPC_IOSystem *system,
                                      PBC_GRPC_IO_SSLServerOptions *options,
                                      PBC_GRPC_Error **error);

PBC_GRPC_IO_Timer *
pbc_grpc_io_system_new_timer         (PBC_GRPC_IOSystem *system,
                                      uint64_t microseconds,
                                      PBC_GRPC_IO_TimerFunc func,
                                      void                 *timer_data);

extern PBC_GRPC_IOSystem * pbc_grpc_io_system;

PBC_GRPC_IOSystem * pbc_grpc_io_system_new_from_dispatch (PBC_GRPC_Dispatch *);


typedef struct PBC_GRPC_Client PBC_GRPC_Client;
typedef struct PBC_GRPC_Server PBC_GRPC_Server;

#include "pbc-grpc-dispatch.h"
#include "pbc-grpc-dns.h"

struct PBC_GRPC_Client_New_Options
{
  /* TODO: other SSL options */
  bool disable_ssl_key_checks;

  /* You can avoid DNS lookups by providing an IP address. */
  bool use_ip_address;
  bool ip_address_is_ipv6;
  uint64_t ip_address[16];

  /* Preconnecting means that we will begin to initiate a
   * new connection whenever we don't have one, whether
   * or not we have an actual request to service.
   *
   * If preconnecting is off, we will only connect
   * when the first request is made.
   *
   * This might give better client performance at the
   * expense of more net traffic and server load.
   */
  bool preconnect;

};

/*
 * Client API.
 */

PBC_GRPC_Client *
pbc_grpc_client_new (PBC_GRPC_Dispatch *dispatch,
                     const char *url,
                     PBC_GRPC_Client_New_Options *options);


/*
 * Create a service that uses this client.
 *
 * Use protobuf_c_service_destroy() to unregister the service.
 * (This will not interfere with running requests to this service.)
 *
 * options must be NULL.
 */
ProtobufCService *
pbc_grpc_client_create_service (PBC_GRPC_Client *client,
                                ProtobufCServiceDescriptor *desc,
                                PBC_GRPC_ClientServiceOptions *options);


void
pbc_grpc_client_destroy (PBC_GRPC_Client *client);


/*
 * Server API.
 */
PBC_GRPC_Server *
pbc_grpc_server_new   (PBC_GRPC_Dispatch *dispatch,
                       PBC_GRPC_Server_New_Options *options);


void
pbc_grpc_server_add_service (PBC_GRPC_Server  *server.
                             ProtobufCService *service,
                             PBC_GRPC_ServerServiceOptions *options);

void
pbc_grpc_server_destroy (PBC_GRPC_Server *server);

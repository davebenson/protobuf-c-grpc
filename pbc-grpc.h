#ifndef __PBC_GRPC_H_
#define __PBC_GRPC_H_

typedef struct PBC_GRPC_Error PBC_GRPC_Error;
typedef struct PBC_GRPC_Client PBC_GRPC_Client;
typedef struct PBC_GRPC_Server PBC_GRPC_Server;

typedef struct PBC_GRPC_Client_New_Options PBC_GRPC_Client_New_Options;

#include <stdbool.h>
#include <stdint.h>
#include "pbc-grpc-dispatch.h"
#include "pbc-grpc-dns.h"

struct PBC_GRPC_Error
{
  unsigned ref_count;
  char *message;
};
PBC_GRPC_Error *pbc_grpc_error_new   (const char     *message);
PBC_GRPC_Error *pbc_grpc_error_ref   (PBC_GRPC_Error *error);
void            pbc_grpc_error_unref (PBC_GRPC_Error *error);

struct PBC_GRPC_Client_New_Options
{
  PBC_GRPC_IOSystem *io_system;

  const char *url;

  bool has_url_in_parts;
  struct {
    const char *hostname;
    int port;
    const char *base_path;
    const char *query;
  } url_parts;


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
pbc_grpc_client_new (
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
typedef struct {
  const char *name_override;
} PBC_GRPC_ClientServiceOptions;
ProtobufCService *
pbc_grpc_client_create_service (PBC_GRPC_Client *client,
                                ProtobufCServiceDescriptor *desc,
                                PBC_GRPC_ClientServiceOptions *options);


void
pbc_grpc_client_destroy (PBC_GRPC_Client *client);


typedef struct {
  PBC_GRPC_IOSystem *io_system;

  int port;
  ... bind ip-address or interface

  // TODO: ip-address restrictions

  ... ssl options
} PBC_GRPC_Server_New_Options;

/*
 * Server API.
 */
PBC_GRPC_Server *
pbc_grpc_server_new   (PBC_GRPC_Server_New_Options *options);


typedef struct {
  const char *name_override;
} PBC_GRPC_Server_ServiceOptions;

void
pbc_grpc_server_add_service (PBC_GRPC_Server  *server.
                             ProtobufCService *service,
                             PBC_GRPC_Server_ServiceOptions *options);

void
pbc_grpc_server_destroy (PBC_GRPC_Server *server);

#endif

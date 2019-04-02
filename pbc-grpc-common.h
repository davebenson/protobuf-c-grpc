#ifndef __PBC_GRPC_COMMON_H_
#define __PBC_GRPC_COMMON_H_

#include <stdbool.h>
#include <stdint.h>

/* An IPv4 or IPv6 address. */
typedef struct {
  bool is_ipv6;
  uint8_t addr[16];
} PBC_GRPC_IPAddress;

/* Structure providing rror information */
typedef struct PBC_GRPC_Error PBC_GRPC_Error;
struct PBC_GRPC_Error
{
  unsigned ref_count;
  char *message;
};
PBC_GRPC_Error *pbc_grpc_error_new   (const char     *message);
PBC_GRPC_Error *pbc_grpc_error_new_printf (const char *format, ...);
PBC_GRPC_Error *pbc_grpc_error_ref   (PBC_GRPC_Error *error);
void            pbc_grpc_error_unref (PBC_GRPC_Error *error);

#endif

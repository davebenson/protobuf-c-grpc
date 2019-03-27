#define PBC_GRPC_DNS_PORT 53

/* DNS only handles IPv4 and IPv6 addresses. */
typedef enum {
  PBC_GRPC_DNS_ADDRESS_TYPE_IPv4,
  PBC_GRPC_DNS_ADDRESS_TYPE_IPv6,
} PBC_GRPC_DNS_AddressType;

/* The number of bytes of addr used depends on 'type':
 * 4 for ipv4, 16 for ipv6
 */
typedef struct {
  PBC_GRPC_DNS_AddressType type;
  uint8_t addr[16];
} PBC_GRPC_DNS_Address;

/* Basic result of a lookup. */
typedef enum PBC_GRPC_DNS_ResultCode
{ 
  /* The lookup resulted in 1 or more addresses. */
  PBC_GRPC_DNS_SUCCESS,

  /* No address was found, and the resolution should fail
   * until the TTL expires. */
  PBC_GRPC_DNS_NOT_FOUND,

  /* The lookup resulted in an error.  Try again later. */
  PBC_GRPC_DNS_ERROR,

  /* The lookup resulted in an error, and it'll never be resolved. */
  PBC_GRPC_DNS_ERROR_PERMANENT
} PBC_GRPC_DNS_ResultCode;

typedef struct {
  PBC_GRPC_DNS_ResultCode code;
  int ttl;
  /* normalized from the query (except possibly in error case) */
  const char *name;

  /* if we had to chase a cname, then this is the last one
   * we used. */
  const char *last_cname;

  /* passed into resolve function */
  void *data;


  union {
    struct {
      size_t n_addresses;
      PBC_GRPC_DNS_Address *addresses;
    } success;
    PBC_GRPC_Error *error;
  };
} PBC_GRPC_DNS_Result;
      
      
typedef void (*PBC_GRPC_DNS_ResolveFunc)(PBC_GRPC_DNS_Result *result);

struct PBC_GRPC_DNS_Resolver 
{
  void (*resolve) (PBC_GRPC_DNS_Resolver     *resolver,
                   PBC_GRPC_Dispatch         *dispatch,
                   const char                *name,
                   PBC_GRPC_DNS_ResolveFunc   func,
                   void                      *data);
};


extern PBC_GRPC_DNS_Resolver pbc_grpc_dns_resolver;
extern PBC_GRPC_DNS_Resolver pbc_grpc_dns_resolver_ipv6;


/* By default, these fields will be set when the
 * DNS resolver is first used, by parsing /etc/resolv.conf,
 * but if you set them first, then we will use your settings.
 */
extern size_t pbc_grpc_dns_n_nameservers;
extern struct PBC_GRPC_DNS_Address *pbc_grpc_dns_nameservers;

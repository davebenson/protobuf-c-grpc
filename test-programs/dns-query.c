#include "../dsk/dsk-cmdline.h"

typedef void
handle_dns_resolution (PBC_GRPC_DNS_Result *result)
{
...
}


int
main (int argc, char **argv)
{
  dsk_cmdline_init ("query DNS",
                    "Query DNS and print IP address",
                    "HOSTNAME");

  dsk_cmdline_add_boolean ("print-ttl",
                           "Print the Time-to-Live with the result",
                           NULL,
                           0,
                           &print_ttl);
  dsk_cmdline_add_boolean ("ipv6",
                           "Request IPv6 address",
                           NULL,
                           0,
                           &ipv6);
  dsk_cmdline_add_string  ("searchpath",
                           "Specify the searchpath (comma-sep)",
                           NULL,
                           0,
                           &searchpath);
  dsk_cmdline_add_string  ("nameservers",
                           "Specify a comma-sep list of IP addresses for nameservers",
                           NULL,
                           0,
                           &nameservers);
  dsk_cmdline_process_args (&argc, &argv);

  PBC_GRPC_DNS_InitConfig config = PBC_GRPC_DNS_INIT_CONFIG_INIT;
  config.use_ipv6_by_default = ipv6;
  pbc_grpc_dns_init (&config);

  if (argc != 2)
    {
      fprintf(stderr, "exactly one argument expected: the hostname\n");
      return 1;
    }

  PBC_GRPC_Dispatch *dispatch = pbc_grpc_dispatch_new();
  pbc_grpc_dns_resolver->resolve (pbc_grpc_dns_resolver,
                                  dispatch,
                                  argv[1],
                                  handle_dns_resolution,
                                  NULL);
  while (!done)
    pbc_grpc_dispatch_run (pbc_grpc_dispatch);

  return 0;
}

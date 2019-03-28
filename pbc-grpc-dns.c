#define PBC_GRPC_DNS_PORT 53

typedef struct EtcHostsEntry EtcHostsEntry;
struct EtcHostsEntry
{
  char *name;
  PBC_GRPC_DNS_Address address;
};

static size_t n_searchpath_entries;
static char **searchpath_entries;
static size_t n_etc_hosts_ipv4;
static EtcHostsEntry *etc_hosts_ipv4;
static size_t n_etc_hosts_ipv6;
static EtcHostsEntry *etc_hosts_ipv6;
static bool pbc_grpc_dns_initialized = false;
static int dns_fd = -1;
      

typedef struct DNSTask DNSTask;
struct DNSTask
{
  // links for the tree of sessions by id
  DNSTask *sid_left, *sid_right, *sid_parent;
  bool sid_is_red;

  uint16_t session_id;

  unsigned n_names;
  char **names;

  unsigned searchpath_index;
};

typedef void (*PBC_GRPC_DNS_ResolveFunc)(PBC_GRPC_DNS_Result *result);
static void
do_init (PBC_GRPC_DNS_InitConfig *config)
{
  FILE *cp;

  /* Parse /etc/hosts */
  if (config->use_etc_hosts)
    {
      const char *fname = config->etc_hosts_filename;
      fp = fopen (fname, "r");
      if (fp == NULL)
        {
          if (config->warn_about_problems)
            fprintf(stderr, "could not open %s: %s",
                    fname, strerror (errno));
        }
      else
        {
          lineno = 0;
          while (fgets (buf, sizeof (buf), fp) != NULL)
            {
              char *at = buf;
              const char *ip;
              const char *name;
              DskIpAddress addr;
              DskDnsCacheEntry *host_entry;
              ++lineno;
              DSK_ASCII_SKIP_SPACE (at);
              if (*at == '#')
                continue;
              if (*at == 0)
                continue;
              ip = at;
              DSK_ASCII_SKIP_NONSPACE (at);
              *at++ = 0;
              DSK_ASCII_SKIP_SPACE (at);
              name = at;
              DSK_ASCII_SKIP_NONSPACE (at);
              *at = 0;
              if (*ip == 0 || *name == 0)
                {
                  dsk_warning ("parsing /etc/hosts line %u: expected ip/name pair",
                               lineno);
                  continue;
                }
              if (!dsk_ip_address_parse_numeric (ip, &addr))
                {
                  dsk_warning ("parsing /etc/hosts line %u: error parsing ip address",
                               lineno);
                  continue;
                }
              host_entry = dsk_malloc (sizeof (DskDnsCacheEntry)
                                       + strlen (name) + 1);

              host_entry->info.addr.addresses = DSK_NEW (DskIpAddress);
              host_entry->info.addr.addresses[0] = addr;
              host_entry->name = (char*)(host_entry + 1);
              strcpy (host_entry->name, name);
              for (at = host_entry->name; *at; at++)
                if (dsk_ascii_isupper (*at))
                  *at += ('a' - 'A');

              host_entry->is_ipv6 = addr.type == DSK_IP_ADDRESS_IPV6;
              host_entry->expire_time = NO_EXPIRE_TIME;
              host_entry->type = DSK_DNS_CACHE_ENTRY_ADDR;
              host_entry->info.addr.n = 1;
              host_entry->info.addr.i = 0;
              host_entry->info.addr.addresses[0] = addr;
        retry:
              DSK_RBTREE_INSERT (GET_ETC_HOSTS_TREE (), host_entry, conflict);
              if (conflict != NULL)
                {
                  DSK_RBTREE_REMOVE (GET_ETC_HOSTS_TREE (), conflict);
                  goto retry;
                }
            }
        }
      fclose (fp);
    }

  /* Parse /etc/resolv.conf */
  if (config->use_resolv_conf_searchpaths
   || config->use_resolv_conf_nameservers)
    {
      fp = fopen ("/etc/resolv.conf", "r");
      if (fp == NULL)
        {
          if (config->warn_about_problems)
            {
              fprintf(stderr, "protobuf-c-grpc: could not open /etc/resolv.conf: %s\n",
                      strerror(errno));
            }
        }
      else
        {
          lineno = 0;
          while (fgets (buf, sizeof (buf), fp) != NULL)
            {
              char *at = buf;
              char *command, *arg;
              ++lineno;
              while (*at && dsk_ascii_isspace (*at))
                at++;
              if (*at == '#')
                continue;
              DSK_ASCII_SKIP_SPACE (at);
              if (*at == '#')
                continue;
              command = at;
              while (*at && !dsk_ascii_isspace (*at))
                {
                  if ('A' <= *at && *at <= 'Z')
                    *at += ('a' - 'Z');
                  at++;
                }
              *at++ = 0;
              DSK_ASCII_SKIP_SPACE (at);
              arg = at;
              DSK_ASCII_SKIP_NONSPACE (at);
              *at = 0;
              if (strcmp (command, "search") == 0)
                {
                  const char *in;
                  char *out;
                  dsk_boolean dot_allowed;
                  unsigned i;

                  /* Add a searchpath to the list. */

                  /* normalize argument (lowercase; check syntax) */
                  in = out = arg;
                  dot_allowed = DSK_FALSE;
                  while (*in)
                    {
                      if (*in == '.')
                        {
                          if (dot_allowed)
                            {
                              *out++ = '.';
                              dot_allowed = DSK_FALSE;
                            }
                        }
                      else if ('A' <= *in && *in <= 'Z')
                        {
                          dot_allowed = DSK_TRUE;
                          *out++ = *in + ('a' - 'A');
                        }
                      else if (('0' <= *in && *in <= '9')
                            || ('a' <= *in && *in <= 'z')
                            || (*in == '-')
                            || (*in == '_'))
                        {
                          dot_allowed = DSK_TRUE;
                          *out++ = *in;
                        }
                      else
                        {
                          dsk_warning ("disallowed character '%c' in searchpath in /etc/resolv.conf line %u", *in, lineno);
                          goto next_line_of_etc_resolv_conf;
                        }
                      in++;
                    }
                  *out = 0;

                  /* remove trailing dot, if it exists */
                  if (!dot_allowed && out > arg)
                    *(out-1) = 0;

                  if (*arg == 0)
                    {
                      dsk_warning ("empty searchpath entry in /etc/resolv.conf (line %u)", lineno);
                      goto next_line_of_etc_resolv_conf;
                    }

                  /* add if not already in set */
                  for (i = 0; i < n_resolv_conf_search_paths; i++)
                    if (strcmp (arg, resolv_conf_search_paths[i]) == 0)
                      {
                        dsk_warning ("match: searchpath[%u] = %s", i, resolv_conf_search_paths[i]);
                        break;
                      }
                  if (i < n_resolv_conf_search_paths)
                    {
                      dsk_warning ("searchpath '%s' appears twice in /etc/resolv.conf (line %u)",
                                   arg, lineno);
                    }
                  else
                    {
                      unsigned length = strlen (arg);
                      resolv_conf_search_paths = DSK_RENEW (char *,
                                                    resolv_conf_search_paths,
                                                    n_resolv_conf_search_paths + 1);
                      if (max_resolv_conf_searchpath_len < length)
                        max_resolv_conf_searchpath_len = length;
                      resolv_conf_search_paths[n_resolv_conf_search_paths++] = dsk_strdup (arg);
                    }
                }
              else if (strcmp (command, "nameserver") == 0)
                {
                  /* add nameserver */
                  DskIpAddress addr;
                  unsigned i;
                  if (!dsk_ip_address_parse_numeric (arg, &addr))
                    {
                      dsk_warning ("in /etc/resolv.conf, line %u: error parsing ip address", lineno);
                      goto next_line_of_etc_resolv_conf;
                    }
                  for (i = 0; i < n_resolv_conf_ns; i++)
                    if (dsk_ip_addresses_equal (&resolv_conf_ns[i].address, &addr))
                      break;
                  if (i < n_resolv_conf_ns)
                    {
                      dsk_warning ("in /etc/resolv.conf, line %u: nameserver %s already exists", lineno, arg);
                    }
                  else
                    {
                      resolv_conf_ns = DSK_RENEW (NameserverInfo, resolv_conf_ns,
                                                  n_resolv_conf_ns + 1);
                      nameserver_info_init (&resolv_conf_ns[n_resolv_conf_ns++], &addr);
                    }
                }
              else
                {
                  dsk_warning ("unknown command '%s' in /etc/resolv.conf line %u",
                               command, lineno);
                }
        next_line_of_etc_resolv_conf:
              ;
            }
          fclose (fp);
        }
    }

  if (!config->use_resolv_conf_searchpaths)
    {
      ... use alternate searchpaths
    }
  if (!config->use_resolv_conf_nameservers)
    {
      ... use alternate nameservers
    }

  if (n_nameservers == 0 && config->warn_about_problems)
    {
      ...
    }

  if (config->use_ipv6_by_default)
    pbc_grpc_dns_resolver = pbc_grpc_dns_resolver_ipv6;

  /* create a file-descriptor for sending and receiving DNS messages */
  ...

}

void
pbc_grpc_dns_init (PBC_GRPC_DNS_InitConfig *config)
{
  assert (!pbc_grpc_dns_initialized);
  do_init (config);
  pbc_grpc_dns_initialized = true;
}

static void
init_defaults (void)
{
  RBC_GRPC_DNS_InitConfig config = PBC_GRPC_DNS_INIT_CONFIG_INIT;
  pbc_grpc_dns_init (&config);
}

struct BuiltinResolver
{
  PBC_GRPC_DNS_Resolver base_instance;
  PBC_GRPC_DNS_AddressType address_type;

  uint16_t next_session_id;
};

static bool
allocate_id (BuiltinResolver *res, uint16_t *out, PBC_GRPC_Error **error)
{
  if (res->n_tasks == (1<<16))
    {
      *error = pbc_grpc_error_new ("too many active tasks");
      return false;
    }

  for (;;)
    {
      uint16_t sid = res->next_session_id++;
      DSKTask *out;
      DSK_RBTREE_LOOKUP_COMPARATOR (GET_SESSION_ID_TREE (res),
                                    sid, COMPARE_DSK_TASK_TO_SESSION_ID,
                                    out);
      if (out == NULL)
        return sid;
    }
}

static void
pack_question (BuiltinResolver *res,
               DNSTask         *task,
               size_t          *msg_len_out,
               uint8_t        **msg_data_out)
{
  DskDnsQuestion questions[1];
  bool must_free_name = false;
  if (task->n_names == 1)
    {
      if (searchpath_index == n_searchpath_entries)
        {
          questions[0].name = nname;
        }
      else
        {
          // concat searchpath with nname
          ...
          questions[0].name = nname;
          must_free_name = true;
        }
    }
  else
    {
      questions[0].name = task->names[task->n_names - 1];
    }
  questions[0].query_class = DSK_DNS_CLASS_IN;
  switch (address_type) {
    case PBC_GRPC_DNS_ADDRESS_TYPE_IPv4:
      questions[0].query_type = DSK_DNS_RR_HOST_ADDRESS;
      break;
    case PBC_GRPC_DNS_ADDRESS_TYPE_IPv6:
      questions[0].query_type = DSK_DNS_RR_HOST_ADDRESS_IPV6;
      break;
    default:
      result.code = PBC_GRPC_DNS_ERROR_PERMANENT;
      result.error = pbc_grpc_error_new ("address-type invalid");
      result.data = data;
      func (&result);
      pbc_grpc_error_unref (result.error);
      free (nname);
      return;
  }

  memset (&message, 0, sizeof (message);
  message->n_questions = 1;
  message->questions = questions;
  message->id = session_id;
  message->is_query = 1;
  message->recursion_desired = 1;
  message->opcode = DSK_DNS_OP_QUERY;

  *msg_data_out = pbc_grpc_dsk_dns_message_serialize (message, msg_len_out);

  if (must_free_name)
    free ((void *) questions[0].name);
}

static void
ask_question_or_terminate (BuiltinResolver *res,
                           DNSTask         *task)
{
  /* trap readable */
  if (!dns_fd_is_trapped)
    {
      ...ZZ
    }

  const char *name = compute_name (res, task, &must_free_name);

  EtcHostsEntry *entry = lookup_etc_hosts_entry (name);
  if (entry != NULL)
    {
      PBC_GRPC_DNS_Result result;
      result.code = PBC_GRPC_DNS_SUCCESS;
      result.success....
      result.ttl = ETC_HOSTS_TTL;
      result.data = task->data;
      task->func (&result);
      free_task (res, task);
      if (must_free_name)
        free ((char *) name);
      return;
    }

  pack_question (builtin_resolver, task, &qlen, &qdata);
  ssize_t send_rv = sendto (dns_fd, qdata, qlen, 0, /* flags */
                            &dst, dst_len);
  if (send_rv < 0)
    {
      if (errno == EINTR)
        goto retry;
      // should EAGAIN trigger a queuing operation?
    }
  else if (send_rv < qlen)
    {
      // partial write.  treat as permanent error?
      PBC_GRPC_DNS_Result result;
      result.code = PBC_GRPC_DNS_ERROR_PERMANENT;
      result.error = pbc_grpc_error_new ("partial write to UDP socket");
      result.data = task->data;
      task->func (&result);
    }
  else
    {
      // success!
    }
}

static void
builtin_resolver_resolve (PBC_GRPC_DNS_Resolver     *resolver,
                          PBC_GRPC_Dispatch         *dispatch,
                          const char                *name,
                          PBC_GRPC_DNS_ResolveFunc   func,
                          void                      *data)
{
  BuiltinResolver *builtin_resolver = (BuiltinResolver *) resolver;
  PBC_GRPC_DNS_AddressType address_type = builtin_resolver->address_type;
  PBC_GRPC_DskDnsMessage message;
  PBC_GRPC_Error *error;
  PBC_GRPC_DNS_Result result;

  if (!pbc_grpc_dns_initialized)
    init_defaults ();

  char *nname = normalize_name (name, &use_searchpath);
  if (nname == NULL)
    {
      result.code = PBC_GRPC_DNS_ERROR_PERMANENT;
      result.error = pbc_grpc_error_new ("name invalid");
      result.data = data;
      func (&result);
      pbc_grpc_error_unref (result.error);
      return;
    }

  uint16_t session_id;
  if (!allocate_id (builtin_resolver, &session_id, &result.error))
    {
      result.code = PBC_GRPC_DNS_ERROR_PERMANENT;
      result.data = data;
      func (&result);
      pbc_grpc_error_unref (result.error);
      return;
    }

  DNSTask *task = NEW (DNSTask);
  task->session_id = session_id;
  task->n_names = 1;
  task->names = NEW_ARRAY (char *, 1);
  task->names[0] = nname;
  task->searchpath_index = use_searchpath ? 0 : n_searchpath_entries;
  DSK_RBTREE_INSERT (GET_SESSION_ID_TREE (builtin_resolver), task);

  task->overall_timer = pbc_grpc_dispatch_add_timer (dispatch, ...);

  ask_question_or_terminate (builtin_resolver, task);
}

static BuiltinResolver pbc_grpc_dns_resolver_instance = {
  { builtin_resolver_resolve },
  PBC_GRPC_DNS_ADDRESS_TYPE_IPv4
};
PBC_GRPC_DNS_Resolver *pbc_grpc_dns_resolver_ipv4 = (PBC_GRPC_DNS_Resolver *) &pbc_grpc_dns_resolver_instance;

static BuiltinResolver pbc_grpc_dns_resolver_instance = {
  { builtin_resolver_resolve },
  PBC_GRPC_DNS_ADDRESS_TYPE_IPv6
};
PBC_GRPC_DNS_Resolver *pbc_grpc_dns_resolver_ipv6 = (PBC_GRPC_DNS_Resolver *) &pbc_grpc_dns_resolver_ipv6_instance;

PBC_GRPC_DNS_Resolver *pbc_grpc_dns_resolver = (PBC_GRPC_DNS_Resolver *) &pbc_grpc_dns_resolver_instance;


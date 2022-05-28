#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include <sstream>
#include <iomanip>
#include <fstream>

#include "log.h"
#include "dnsparser.h"
#include "dnscachedresolver.h"
#include "static_dns_cache.h"
#include "sas.h"
#include "sasevent.h"
#include "cpp_common_pd_definitions.h"

DnsResult::DnsResult(const std::string& domain,
                     int dnstype,
                     const std::vector<DnsRRecord*>& records,
                     int ttl) :
  _domain(domain),
  _dnstype(dnstype),
  _records(),
  _ttl(ttl)
{
  for (std::vector<DnsRRecord*>::const_iterator i = records.begin();
       i != records.end();
       ++i)
  {
    _records.push_back((*i)->clone());
  }
}

DnsResult::DnsResult(const DnsResult &res) :
  _domain(res._domain),
  _dnstype(res._dnstype),
  _records(),
  _ttl(res._ttl)
{
  for (std::vector<DnsRRecord*>::const_iterator i = res._records.begin();
       i != res._records.end();
       ++i)
  {
    _records.push_back((*i)->clone());
  }
}

DnsResult::DnsResult(DnsResult &&res) :
  _domain(res._domain),
  _dnstype(res._dnstype),
  _records(),
  _ttl(res._ttl)
{
  for (std::vector<DnsRRecord*>::const_iterator i = res._records.begin();
       i != res._records.end();
       ++i)
  {
    _records.push_back(*i);
  }

  res._records.clear();
}

DnsResult::DnsResult(const std::string& domain,
                     int dnstype,
                     int ttl) :
  _domain(domain),
  _dnstype(dnstype),
  _records(),
  _ttl(ttl)
{
}

DnsResult::~DnsResult()
{
  while (!_records.empty())
  {
    delete _records.back();
    _records.pop_back();
  }
}

void DnsCachedResolver::init(const std::vector<IP46Address>& dns_servers)
{
  _dns_servers = dns_servers;
  _cache_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
  TRC_DEBUG("Timeout = %d", _timeout);

  ares_library_init(ARES_LIB_INIT_ALL);

  pthread_key_create(&_thread_local, (void(*)(void*))&destroy_dns_channel);

  pthread_condattr_t cond_attr;
  pthread_condattr_init(&cond_attr);
  pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
  pthread_cond_init(&_got_reply_cond, &cond_attr);
  pthread_condattr_destroy(&cond_attr);
}

void DnsCachedResolver::init_from_server_ips(const std::vector<std::string>& dns_servers)
{
  std::vector<IP46Address> dns_server_ips;

  TRC_STATUS("Creating Cached Resolver using servers:");
  for (size_t i = 0; i < dns_servers.size(); i++)
  {
    if (dns_servers[i] == "0.0.0.0")
    {
      continue;
    }

    IP46Address addr;
    TRC_STATUS("    %s", dns_servers[i].c_str());
    if (inet_pton(AF_INET, dns_servers[i].c_str(), &(addr.addr.ipv4)))
    {
      addr.af = AF_INET;
    }
    else if (inet_pton(AF_INET6, dns_servers[i].c_str(), &(addr.addr.ipv6)))
    {
      addr.af = AF_INET6;
    }
    else
    {
      TRC_ERROR("Failed to parse '%s' as IP address - defaulting to 127.0.0.1", dns_servers[i].c_str());
      addr.af = AF_INET;
      (void)inet_aton("127.0.0.1", &(addr.addr.ipv4));
    }
    dns_server_ips.push_back(addr);
  }

  init(dns_server_ips);
}


DnsCachedResolver::DnsCachedResolver(const std::vector<IP46Address>& dns_servers,
                                     int timeout,
                                     const std::string& filename,
                                     int port) :
  _port(port),
  _timeout(timeout),
  _cache(),
  _static_cache(filename)
{
  init(dns_servers);
}

DnsCachedResolver::DnsCachedResolver(const std::vector<std::string>& dns_servers,
                                     int timeout,
                                     const std::string& filename,
                                     int port) :
  _port(port),
  _timeout(timeout),
  _cache(),
  _static_cache(filename)
{
  init_from_server_ips(dns_servers);
}

DnsCachedResolver::DnsCachedResolver(const std::string& dns_server,
                                     int timeout,
                                     const std::string& filename,
                                     int port) :
  _port(port),
  _timeout(timeout),
  _cache(),
  _static_cache(filename)
{
  init_from_server_ips({dns_server});
}

DnsCachedResolver::~DnsCachedResolver()
{
  DnsChannel* channel = (DnsChannel*)pthread_getspecific(_thread_local);
  if (channel != NULL)
  {
    pthread_setspecific(_thread_local, NULL);
    destroy_dns_channel(channel);
  }
  pthread_key_delete(_thread_local);

  clear();
}

void DnsCachedResolver::reload_static_records()
{
  pthread_mutex_lock(&_cache_lock);
  _static_cache.reload_static_records();
  pthread_mutex_unlock(&_cache_lock);
}

DnsResult DnsCachedResolver::dns_query(const std::string& domain,
                                       int dnstype,
                                       SAS::TrailId trail)
{
  std::vector<DnsResult> res;
  std::vector<std::string> domains;
  domains.push_back(domain);

  dns_query(domains, dnstype, res, trail);

  return res.front();
}

void DnsCachedResolver::dns_query(const std::vector<std::string>& domains,
                                  int dnstype,
                                  std::vector<DnsResult>& results,
                                  SAS::TrailId trail)
{
  std::vector<std::string> domains_to_query;

  std::map<std::string, std::string> canonical_map;

  std::map<std::string, DnsResult> result_map;

  pthread_mutex_lock(&_cache_lock);

  for (const std::string& domain : domains)
  {
    TRC_DEBUG("Searching for DNS record matching %s in the static cache", domain.c_str());

    std::string canonical_domain = _static_cache.get_canonical_name(domain);
    canonical_map.insert(std::pair<std::string,std::string>(domain, canonical_domain));

    DnsResult static_result = _static_cache.get_static_dns_records(canonical_domain, dnstype);
    if (!static_result.records().empty())
    {
      TRC_DEBUG("%s found in the static cache", canonical_domain.c_str());
      result_map.insert(std::pair<std::string, DnsResult>(canonical_domain, static_result));
    }
    else
    {
      TRC_DEBUG("%s not found in the static cache", canonical_domain.c_str());
      domains_to_query.push_back(canonical_domain);
    }
  }

  inner_dns_query(domains_to_query, dnstype, result_map, trail);

  for (const std::string& domain : domains)
  {
    std::string canonical_domain = canonical_map.at(domain);
    if (result_map.count(canonical_domain) > 0)
    {
      TRC_DEBUG("Found result for query %s (canonical domain: %s)",
                domain.c_str(),
                canonical_domain.c_str());
      results.push_back(result_map.at(canonical_domain));
    }
  }

  pthread_mutex_unlock(&_cache_lock);
}

void DnsCachedResolver::inner_dns_query(const std::vector<std::string>& domains,
                                        int dnstype,
                                        std::map<std::string, DnsResult>& results,
                                        SAS::TrailId trail)
{
  DnsChannel* channel = NULL;

  expire_cache();

  bool wait_for_query_result = false;
  for (std::vector<std::string>::const_iterator domain = domains.begin();
       domain != domains.end();
       ++domain)
  {
    TRC_VERBOSE("Check cache for %s type %d", domain->c_str(), dnstype);
    DnsCacheEntryPtr ce = get_cache_entry(*domain, dnstype);
    time_t now = time(NULL);
    bool do_query = false;
    if (ce == NULL)
    {
      TRC_DEBUG("No entry found in cache");
      TRC_DEBUG("Create cache entry pending query");
      ce = create_cache_entry(*domain, dnstype, trail);
      do_query = true;
      wait_for_query_result = true;
    }
    else if (ce->expires <= now)
    {

      if (ce->pending_query)
      {
        TRC_DEBUG("Expired entry found in cache - asynchronous query to update it already in progress on another thread");
        if (ce->records.empty())
        {
          wait_for_query_result = true;
        }
      }
      else
      {
        TRC_DEBUG("Expired entry found in cache - starting asynchronous query to update it");
        do_query = true;

        wait_for_query_result = true;
      }

    }

    if (do_query)
    {
      if (channel == NULL)
      {
        channel = get_dns_channel();
      }

      if (channel != NULL)
      {
        TRC_DEBUG("Create and execute DNS query transaction");
        ce->pending_query = true;
        DnsTsx* tsx = new DnsTsx(channel, *domain, dnstype, trail);
        tsx->execute();
      }
    }
  }

  if (channel != NULL && wait_for_query_result)
  {
    TRC_DEBUG("Wait for query responses");
    pthread_mutex_unlock(&_cache_lock);
    CW_IO_STARTS("DNS query")
    {
      wait_for_replies(channel);
    }
    CW_IO_COMPLETES()
    pthread_mutex_lock(&_cache_lock);
    TRC_DEBUG("Received all query responses");
  }

  for (std::vector<std::string>::const_iterator i = domains.begin();
       i != domains.end();
       ++i)
  {
    DnsCacheEntryPtr ce = get_cache_entry(*i, dnstype);
    while ((ce != NULL) && (ce->pending_query) && wait_for_query_result)
    {
      TRC_DEBUG("Waiting for (non-cached) DNS query for %s", i->c_str());
      CW_IO_STARTS("DNS pending query")
      {
        pthread_cond_wait(&_got_reply_cond, &_cache_lock);
      }
      CW_IO_COMPLETES()
      ce = get_cache_entry(*i, dnstype);
      TRC_DEBUG("Reawoken from wait for %s type %d", i->c_str(), dnstype);
    }

    if (ce != NULL)
    {
      TRC_DEBUG("Pulling %d records from cache for %s %s",
                ce->records.size(),
                ce->domain.c_str(),
                DnsRRecord::rrtype_to_string(ce->dnstype).c_str());

      SAS::Event event(trail, SASEvent::DNS_CACHE_USED, 0);
      event.add_static_param(ce->records.size());
      event.add_static_param(ce->original_trail);
      event.add_var_param(ce->domain);
      event.add_var_param(ce->original_time);
      SAS::report_event(event);
      int expiry = ce->expires - time(NULL);
      if (expiry < 0)
      {
        expiry = 0;
      }

      results.insert(std::pair<std::string, DnsResult>(*i, DnsResult(ce->domain,
                                                                     ce->dnstype,
                                                                     ce->records,
                                                                     expiry)));
    }
    else
    {
      TRC_DEBUG("Return empty result set");
      results.insert(std::pair<std::string, DnsResult>(*i, DnsResult(*i, dnstype, 0)));
    }
  }
}

void DnsCachedResolver::add_to_cache(const std::string& domain,
                                     int dnstype,
                                     std::vector<DnsRRecord*>& records)
{
  pthread_mutex_lock(&_cache_lock);
  SAS::TrailId no_trail = 0;

  TRC_DEBUG("Adding cache entry %s %s",
            domain.c_str(), DnsRRecord::rrtype_to_string(dnstype).c_str());

  DnsCacheEntryPtr ce = get_cache_entry(domain, dnstype);

  if (ce == NULL)
  {
    TRC_DEBUG("Create cache entry");
    ce = create_cache_entry(domain, dnstype, no_trail);
  }
  else
  {
    clear_cache_entry(ce);
  }

  for (size_t ii = 0; ii < records.size(); ++ii)
  {
    add_record_to_cache(ce, records[ii], no_trail);
  }

  records.clear();

  add_to_expiry_list(ce);

  pthread_mutex_unlock(&_cache_lock);
}

std::string DnsCachedResolver::display_cache()
{
  std::ostringstream oss;
  pthread_mutex_lock(&_cache_lock);
  expire_cache();
  int now = time(NULL);
  for (DnsCache::const_iterator i = _cache.begin();
       i != _cache.end();
       ++i)
  {
    DnsCacheEntryPtr ce = i->second;
    oss << "Cache entry " << ce->domain
        << " type=" << DnsRRecord::rrtype_to_string(ce->dnstype)
        << " expires=" << ce->expires-now << std::endl;

    for (std::vector<DnsRRecord*>::const_iterator j = ce->records.begin();
         j != ce->records.end();
         ++j)
    {
      oss << (*j)->to_string() << std::endl;
    }
  }
  pthread_mutex_unlock(&_cache_lock);
  return oss.str();
}

void DnsCachedResolver::clear()
{
  TRC_DEBUG("Clearing %d cache entries", _cache.size());
  while (!_cache.empty())
  {
    DnsCache::iterator i = _cache.begin();
    DnsCacheEntryPtr ce = i->second;
    TRC_DEBUG("Deleting cache entry %s %s",
              ce->domain.c_str(),
              DnsRRecord::rrtype_to_string(ce->dnstype).c_str());
    clear_cache_entry(ce);
    _cache.erase(i);
  }
}

void DnsCachedResolver::dns_response(const std::string& domain,
                                     int dnstype,
                                     int status,
                                     unsigned char* abuf,
                                     int alen,
                                     SAS::TrailId trail)
{
  pthread_mutex_lock(&_cache_lock);

  TRC_DEBUG("Received DNS response for %s type %s - status is %d (%s)",
             domain.c_str(),
             DnsRRecord::rrtype_to_string(dnstype).c_str(),
             status,
             ares_strerror(status));

  std::string canonical_domain;

  DnsCacheEntryPtr ce = get_cache_entry(domain, dnstype);

  if (status == ARES_SUCCESS)
  {
    if (trail != 0)
    {
      SAS::Event event(trail, SASEvent::DNS_SUCCESS, 0);
      event.add_static_param(dnstype);
      event.add_var_param(domain);
      event.add_var_param(alen, abuf);
      SAS::report_event(event);
    }

    DnsParser parser(abuf, alen);

    if (parser.parse())
    {
      clear_cache_entry(ce);
      TRC_DEBUG("DNS response for %s - response contains %d answers",
                 domain.c_str(),
                 parser.answers().size());

      while (!parser.answers().empty())
      {
        DnsRRecord* rr = parser.answers().front();
        parser.answers().pop_front();
        if ((rr->rrtype() == ns_t_a) ||
            (rr->rrtype() == ns_t_aaaa))
        {
          if ((strcasecmp(rr->rrname().c_str(), domain.c_str()) == 0) ||
              (strcasecmp(rr->rrname().c_str(), canonical_domain.c_str()) == 0))
          {
            add_record_to_cache(ce, rr, trail);
          }
          else
          {
            TRC_DEBUG("Ignoring A/AAAA record for %s (expecting domain %s)",
                      rr->rrname().c_str(), domain.c_str());
            delete rr;
          }
        }
        else if ((rr->rrtype() == ns_t_srv) ||
                 (rr->rrtype() == ns_t_naptr))
        {
          add_record_to_cache(ce, rr, trail);
        }
        else if (rr->rrtype() == ns_t_cname)
        {
          canonical_domain = ((DnsCNAMERecord*)rr)->target();
          TRC_DEBUG("CNAME record pointing at %s - treating this as equivalent to %s",
                    canonical_domain.c_str(),
                    domain.c_str());
        }
        else
        {
          TRC_WARNING("Ignoring %s record in DNS answer - only CNAME, A, AAAA, NAPTR and SRV are supported",
                      DnsRRecord::rrtype_to_string(rr->rrtype()).c_str());
          delete rr;
        }
      }
      std::map<DnsCacheKey, std::list<DnsRRecord*> > sorted;
      while (!parser.additional().empty())
      {
        DnsRRecord* rr = parser.additional().front();
        parser.additional().pop_front();
        if (caching_enabled(rr->rrtype()))
        {
          sorted[std::make_pair(rr->rrtype(), rr->rrname())].push_back(rr);
        }
        else
        {
          delete rr;
        }
      }

      for (std::map<DnsCacheKey, std::list<DnsRRecord*> >::const_iterator i = sorted.begin();
           i != sorted.end();
           ++i)
      {
        DnsCacheEntryPtr ace = get_cache_entry(i->first.second, i->first.first);
        if (ace == NULL)
        {
          ace = create_cache_entry(i->first.second, i->first.first, trail);
        }
        else
        {
          clear_cache_entry(ace);
        }
        for (std::list<DnsRRecord*>::const_iterator j = i->second.begin();
             j != i->second.end();
             ++j)
        {
          add_record_to_cache(ace, *j, trail);
        }

        add_to_expiry_list(ace);
      }
    }
  }
  else
  {
    TRC_WARNING("Failed to retrieve record for %s: %s", domain.c_str(), ares_strerror(status));

    if (status == ARES_ENOTFOUND)
    {
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::DNS_NOT_FOUND, 0);
        event.add_static_param(dnstype);
        event.add_var_param(domain);
        SAS::report_event(event);
      }

      clear_cache_entry(ce);

      DnsParser parser(abuf, alen);
      if (parser.parse())
      {
        while (!parser.authorities().empty())
        {
          DnsRRecord* rr = parser.authorities().front();
          parser.authorities().pop_front();

          if (rr->rrtype() == ns_t_soa)
          {
            int max_expires = DEFAULT_NEGATIVE_CACHE_TTL + time(NULL);
            ce->expires = std::min(rr->expires(), max_expires);

            delete rr;
            break;
          }
          else
          {
            delete rr;
          }
        }
      }
    }
    else
    {
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::DNS_FAILED, 0);
        event.add_static_param(dnstype);
        event.add_static_param(status);
        event.add_var_param(domain);
        SAS::report_event(event);
      }

      ce->expires = 30 + time(NULL);
    }
  }

  if ((ce->records.empty()) &&
      (ce->expires == 0))
  {
    ce->expires = DEFAULT_NEGATIVE_CACHE_TTL + time(NULL);
  }

  add_to_expiry_list(ce);

  ce->pending_query = false;

  pthread_cond_broadcast(&_got_reply_cond);

  pthread_mutex_unlock(&_cache_lock);
}

bool DnsCachedResolver::caching_enabled(int rrtype)
{
  return (rrtype == ns_t_a) || (rrtype == ns_t_aaaa) || (rrtype == ns_t_srv) || (rrtype == ns_t_naptr);
}

DnsCachedResolver::DnsCacheEntryPtr DnsCachedResolver::get_cache_entry(const std::string& domain, int dnstype)
{
  DnsCache::iterator i = _cache.find(std::make_pair(dnstype, domain));

  if (i != _cache.end())
  {
    return i->second;
  }

  return NULL;
}

DnsCachedResolver::DnsCacheEntryPtr DnsCachedResolver::create_cache_entry(const std::string& domain,
                                                                          int dnstype,
                                                                          SAS::TrailId trail)
{
  DnsCacheEntryPtr ce = DnsCacheEntryPtr(new DnsCacheEntry());
  ce->domain = domain;
  ce->dnstype = dnstype;
  ce->expires = 0;
  ce->pending_query = false;
  ce->original_trail = trail;
  ce->update_timestamp();

  _cache[std::make_pair(dnstype, domain)] = ce;

  return ce;
}

void DnsCachedResolver::add_to_expiry_list(DnsCacheEntryPtr ce)
{
  int sensible_minimum = 1420070400; 
  if ((ce->expires != 0) && (ce->expires < sensible_minimum))
  {
    TRC_WARNING("Cache expiry time is %d - expecting either 0 or an epoch timestamp (> %d)",
                ce->expires,
                sensible_minimum);
  }

  TRC_DEBUG("Adding %s to cache expiry list with deletion time of %d",
            ce->domain.c_str(),
            ce->expires + EXTRA_INVALID_TIME);
  _cache_expiry_list.insert(std::make_pair(ce->expires + EXTRA_INVALID_TIME, std::make_pair(ce->dnstype, ce->domain)));
}

void DnsCachedResolver::expire_cache()
{
  int now = time(NULL);

  while ((!_cache_expiry_list.empty()) &&
         (_cache_expiry_list.begin()->first <= now))
  {
    std::multimap<int, DnsCacheKey>::iterator i = _cache_expiry_list.begin();
    TRC_DEBUG("Removing record for %s (type %d, expiry time %d) from the expiry list", i->second.second.c_str(), i->second.first, i->first);

    DnsCache::iterator j = _cache.find(i->second);
    if (j != _cache.end())
    {
      DnsCacheEntryPtr ce = j->second;

      if (ce->expires + EXTRA_INVALID_TIME == i->first)
      {
        TRC_DEBUG("Expiring record for %s (type %d) from the DNS cache", ce->domain.c_str(), ce->dnstype);
        clear_cache_entry(ce);
        _cache.erase(j);
      }
    }

    _cache_expiry_list.erase(i);
  }
}

void DnsCachedResolver::clear_cache_entry(DnsCacheEntryPtr ce)
{
  while (!ce->records.empty())
  {
    delete ce->records.back();
    ce->records.pop_back();
  }
  ce->expires = 0;
}

void DnsCachedResolver::add_record_to_cache(DnsCacheEntryPtr ce,
                                            DnsRRecord* rr,
                                            SAS::TrailId trail)
{
  TRC_DEBUG("Adding record to cache entry, TTL=%d, expiry=%ld", rr->ttl(), rr->expires());
  ce->original_trail = trail;
  ce->update_timestamp();

  if ((ce->expires == 0) ||
      (ce->expires > rr->expires()))
  {
    TRC_DEBUG("Update cache entry expiry to %ld", rr->expires());
    ce->expires = rr->expires();
  }
  ce->records.push_back(rr);
}

void DnsCachedResolver::wait_for_replies(DnsChannel* channel)
{
  while (channel->pending_queries > 0)
  {
    ares_socket_t scks[ARES_GETSOCK_MAXNUM];
    int rw_bits = ares_getsock(channel->channel, scks, ARES_GETSOCK_MAXNUM);

    int num_fds = 0;
    struct pollfd fds[ARES_GETSOCK_MAXNUM];
    for (int fd_idx = 0; fd_idx < ARES_GETSOCK_MAXNUM; fd_idx++)
    {
      struct pollfd* fd = &fds[fd_idx];
      fd->fd = scks[fd_idx];
      fd->events = 0;
      fd->revents = 0;
      if (ARES_GETSOCK_READABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLRDNORM | POLLIN;
      }
      if (ARES_GETSOCK_WRITABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLWRNORM | POLLOUT;
      }
      if (fd->events != 0)
      {
        num_fds++;
      }
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    (void)ares_timeout(channel->channel, NULL, &tv);

    if (poll(fds, num_fds, tv.tv_sec * 1000 + tv.tv_usec / 1000) != 0)
    {
      for (int fd_idx = 0; fd_idx < num_fds; fd_idx++)
      {
        struct pollfd* fd = &fds[fd_idx];
        if (fd->revents != 0)
        {
          ares_process_fd(channel->channel,
                          fd->revents & (POLLRDNORM | POLLIN) ? fd->fd : ARES_SOCKET_BAD,
                          fd->revents & (POLLWRNORM | POLLOUT) ? fd->fd : ARES_SOCKET_BAD);
        }
      }
    }
    else
    {
      ares_process_fd(channel->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
  }
}

DnsCachedResolver::DnsChannel* DnsCachedResolver::get_dns_channel()
{
  DnsChannel* channel = (DnsChannel*)pthread_getspecific(_thread_local);
  size_t server_count = _dns_servers.size();
  if (server_count > MAX_DNS_SERVER_POLL)
  {
    TRC_WARNING("%d DNS servers provided, only using the first %d",
                _dns_servers.size(),
                MAX_DNS_SERVER_POLL);
    server_count = MAX_DNS_SERVER_POLL;
  }

  if ((channel == NULL) &&
      (server_count > 0))
  {
    channel = new DnsChannel;
    channel->pending_queries = 0;
    channel->resolver = this;
    struct ares_options options;

    options.flags = ARES_FLAG_STAYOPEN;
    options.timeout = _timeout / server_count;
    options.tries = 1;
    options.ndots = 0;
    options.udp_port = _port;
    options.servers = NULL;
    options.nservers = 0;
    ares_init_options(&channel->channel,
                      &options,
                      ARES_OPT_FLAGS |
                      ARES_OPT_TIMEOUTMS |
                      ARES_OPT_TRIES |
                      ARES_OPT_NDOTS |
                      ARES_OPT_UDP_PORT |
                      ARES_OPT_SERVERS);

    for (size_t ii = 0;
         ii < server_count;
         ii++)
    {
      IP46Address server = _dns_servers[ii];
      struct ares_addr_node* ares_addr = &_ares_addrs[ii];
      memset(ares_addr, 0, sizeof(struct ares_addr_node));
      if (ii > 0)
      {
        int prev_idx = ii - 1;
        _ares_addrs[prev_idx].next = ares_addr;
      }

      ares_addr->family = server.af;
      if (server.af == AF_INET)
      {
        memcpy(&ares_addr->addr.addr4, &server.addr.ipv4, sizeof(ares_addr->addr.addr4));
      }
      else
      {
        memcpy(&ares_addr->addr.addr6, &server.addr.ipv6, sizeof(ares_addr->addr.addr6));
      }
    }

    ares_set_servers(channel->channel, _ares_addrs);

    pthread_setspecific(_thread_local, channel);
  }

  return channel;
}

void DnsCachedResolver::destroy_dns_channel(DnsChannel* channel)
{
  ares_destroy(channel->channel);
  delete channel;
}

DnsCachedResolver::DnsTsx::DnsTsx(DnsChannel* channel, const std::string& domain, int dnstype, SAS::TrailId trail) :
  _channel(channel),
  _domain(domain),
  _dnstype(dnstype),
  _trail(trail)
{
}

DnsCachedResolver::DnsTsx::~DnsTsx()
{
}

void DnsCachedResolver::DnsTsx::execute()
{
  ++_channel->pending_queries;

  if (_trail != 0)
  {
    SAS::Event event(_trail, SASEvent::DNS_LOOKUP, 0);
    event.add_static_param(_dnstype);
    event.add_var_param(_domain);
    SAS::report_event(event);
  }

  TRC_DEBUG("Executing DNS lookup for %s (type %s)",
             _domain.c_str(),
             DnsRRecord::rrtype_to_string(_dnstype).c_str());

  ares_query(_channel->channel,
             _domain.c_str(),
             ns_c_in,
             _dnstype,
             DnsTsx::ares_callback,
             this);
}

void DnsCachedResolver::DnsTsx::ares_callback(void* arg,
                                              int status,
                                              int timeouts,
                                              unsigned char* abuf,
                                              int alen)
{
  ((DnsTsx*)arg)->ares_callback(status, timeouts, abuf, alen);
}


void DnsCachedResolver::DnsTsx::ares_callback(int status, int timeouts, unsigned char* abuf, int alen)
{
  if (timeouts > 0)
  {
    TRC_ERROR("Resolution of %s timed out", _domain.c_str());
    SAS::Event event(_trail, SASEvent::DNS_TIMEOUT, 0);
    event.add_static_param(_dnstype);
    event.add_static_param(timeouts);
    event.add_var_param(_domain);
    SAS::report_event(event);
  }

  _channel->resolver->dns_response(_domain, _dnstype, status, abuf, alen, _trail);
  --_channel->pending_queries;
  delete this;
}


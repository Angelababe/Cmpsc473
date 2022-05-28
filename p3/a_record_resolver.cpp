
#include <atomic>
#include "utils.h"
#include "log.h"
#include "a_record_resolver.h"

ARecordResolver::ARecordResolver(DnsCachedResolver* dns_client,
                                 int address_family,
                                 int blacklist_duration,
                                 int graylist_duration,
                                 const int default_port) :
  BaseResolver(dns_client),
  _address_family(address_family),
  _default_port(default_port)
{
  TRC_DEBUG("Creating ARecordResolver");

  // Create the blacklist.
  create_blacklist(blacklist_duration, graylist_duration);

  TRC_STATUS("Created ARecordResolver");
}

ARecordResolver::~ARecordResolver()
{
  destroy_blacklist();
}

void ARecordResolver::resolve(const std::string& host,
                              int port,
                              int max_targets,
                              std::vector<AddrInfo>& targets,
                              SAS::TrailId trail,
                              int allowed_host_state)
{
  BaseAddrIterator* addr_it = resolve_iter(host, port, trail, allowed_host_state);
  targets = addr_it->take(max_targets);
  delete addr_it; addr_it = nullptr;
}

BaseAddrIterator* ARecordResolver::resolve_iter(const std::string& host,
                                                int port,
                                                SAS::TrailId trail,
                                                int allowed_host_state)
{
  BaseAddrIterator* addr_it;

  TRC_DEBUG("ARecordResolver::resolve_iter for host %s, port %d, family %d",
            host.c_str(), port, _address_family);

  port = (port != 0) ? port : _default_port;
  AddrInfo ai;

  if (Utils::parse_ip_target(host, ai.address))
  {
    TRC_DEBUG("Target is an IP address");
    ai.port = port;
    ai.transport = TRANSPORT;

    std::vector<AddrInfo> targets;

    if (select_address(ai, trail, allowed_host_state))
    {
      targets.push_back(ai);
    }

    addr_it = new SimpleAddrIterator(targets);
  }
  else
  {
    int dummy_ttl = 0;
    addr_it = a_resolve_iter(
      host, _address_family, port, TRANSPORT, dummy_ttl, trail, allowed_host_state);
  }

  return addr_it;
}

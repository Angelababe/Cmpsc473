#include <atomic>
#include "utils.h"
#include "log.h"
#include "log.h"
#include "astaire_resolver.h"

static const uint16_t PORT = 11311;
static const int TRANSPORT = IPPROTO_TCP;


AstaireResolver::AstaireResolver(DnsCachedResolver* dns_client,
                                 int address_family,
                                 int blacklist_duration) :
  BaseResolver(dns_client),
  _address_family(address_family)
{
  create_blacklist(blacklist_duration);
}


AstaireResolver::~AstaireResolver()
{
  destroy_blacklist();
}


void AstaireResolver::resolve(const std::string& host,
                              int max_targets,
                              std::vector<AddrInfo>& targets,
                              SAS::TrailId trail)
{
  std::string host_without_port;
  int port;
  AddrInfo ai;
  int dummy_ttl = 0;

  TRC_DEBUG("AstaireResolver::resolve for host %s, family %d",
            host.c_str(), _address_family);

  targets.clear();

  if (!Utils::split_host_port(host, host_without_port, port))
  {
    host_without_port = host;
    port = PORT;
  }

  if (Utils::parse_ip_target(host_without_port, ai.address))
  {
    TRC_DEBUG("Target is an IP address");
    ai.port = port;
    ai.transport = TRANSPORT;
    targets.push_back(ai);
  }
  else
  {
    a_resolve(host_without_port,
              _address_family,
              port,
              TRANSPORT,
              max_targets,
              targets,
              dummy_ttl,
              trail);
  }
}

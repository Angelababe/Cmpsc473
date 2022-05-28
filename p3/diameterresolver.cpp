#include <atomic>
#include "log.h"
#include "diameterresolver.h"

DiameterResolver::DiameterResolver(DnsCachedResolver* dns_client,
                                   int address_family,
                                   int blacklist_duration) :
  BaseResolver(dns_client),
  _address_family(address_family)
{
  TRC_DEBUG("Creating Diameter resolver");

  // Create the NAPTR cache.
  std::map<std::string, int> naptr_services;
  naptr_services["AAA+D2T"] = IPPROTO_TCP;
  naptr_services["AAA+D2S"] = IPPROTO_SCTP;
  naptr_services["aaa:diameter.tcp"] = IPPROTO_TCP;
  naptr_services["aaa:diameter.sctp"] = IPPROTO_SCTP;
  create_naptr_cache(naptr_services);

  create_srv_cache();
  create_blacklist(blacklist_duration);

  TRC_STATUS("Created Diameter resolver");
}

DiameterResolver::~DiameterResolver()
{
  destroy_blacklist();
  destroy_srv_cache();
  destroy_naptr_cache();
}

void DiameterResolver::resolve(const std::string& realm,
                               const std::string& host,
                               int max_targets,
                               std::vector<AddrInfo>& targets,
                               int& ttl)
{
  targets.clear();
  int new_ttl = 0;
  ttl = 0;
  bool set_ttl = false;

  AddrInfo ai;
  int transport = DEFAULT_TRANSPORT;
  std::string srv_name;
  std::string a_name;

  TRC_DEBUG("DiameterResolver::resolve for realm %s, host %s, family %d",
            realm.c_str(), host.c_str(), _address_family);

  if (realm != "")
  {
    TRC_DEBUG("Do NAPTR look-up for %s", realm.c_str());

    std::shared_ptr<NAPTRReplacement> naptr = _naptr_cache->get(realm, ttl, 0);

    if (naptr != NULL)
    {
      set_ttl = true;
      TRC_DEBUG("NAPTR resolved to transport %d", naptr->transport);
      transport = naptr->transport;
      if (strcasecmp(naptr->flags.c_str(), "S") == 0)
      {
        srv_name = naptr->replacement;
      }
      else
      {
        a_name = naptr->replacement;
      }
    }
    else
    {
      TRC_DEBUG("NAPTR lookup failed, so do SRV lookups for TCP and SCTP");

      std::vector<std::string> domains;
      domains.push_back("_diameter._tcp." + realm);
      domains.push_back("_diameter._sctp." + realm);
      std::vector<DnsResult> results;
      _dns_client->dns_query(domains, ns_t_srv, results, 0);
      DnsResult& tcp_result = results[0];
      TRC_DEBUG("TCP SRV record %s returned %d records",
                tcp_result.domain().c_str(), tcp_result.records().size());
      DnsResult& sctp_result = results[1];
      TRC_DEBUG("SCTP SRV record %s returned %d records",
                sctp_result.domain().c_str(), sctp_result.records().size());

      if (!tcp_result.records().empty())
      {
        TRC_DEBUG("TCP SRV lookup successful, select TCP transport");
        transport = IPPROTO_TCP;
        srv_name = tcp_result.domain();
        ttl = tcp_result.ttl();
        set_ttl = true;
      }
      else if (!sctp_result.records().empty())
      {
        TRC_DEBUG("SCTP SRV lookup successful, select SCTP transport");
        transport = IPPROTO_SCTP;
        srv_name = sctp_result.domain();
        ttl = sctp_result.ttl();
        set_ttl = true;
      }
    }

    if (srv_name != "")
    {
      TRC_DEBUG("Do SRV lookup for %s", srv_name.c_str());
      srv_resolve(srv_name, _address_family, transport, max_targets, targets, new_ttl, 0);
      ttl = set_ttl ? std::min(ttl, new_ttl) : new_ttl;
      set_ttl = true;
    }
    else if (a_name != "")
    {
      TRC_DEBUG("Do A/AAAA lookup for %s", a_name.c_str());
      a_resolve(a_name, _address_family, DEFAULT_PORT, transport, max_targets, targets, new_ttl, 0);
      ttl = set_ttl ? std::min(ttl, new_ttl) : new_ttl;
      set_ttl = true;
    }
  }

  if ((targets.empty()) && (host != ""))
  {
    if (Utils::parse_ip_target(host, ai.address))
    {
      TRC_DEBUG("Target is an IP address - default port/transport");
      ai.transport = DEFAULT_TRANSPORT;
      ai.port = DEFAULT_PORT;
      targets.push_back(ai);
    }
    else
    {
      a_resolve(host, _address_family, DEFAULT_PORT, DEFAULT_TRANSPORT, max_targets, targets, new_ttl, 0);
      ttl = set_ttl ? std::min(ttl, new_ttl) : new_ttl;
    }
  }
}

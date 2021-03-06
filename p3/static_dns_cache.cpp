#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include <sstream>
#include <iomanip>
#include <fstream>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"

#include "log.h"
#include "dnsparser.h"
#include "dnscachedresolver.h"
#include "static_dns_cache.h"
#include "cpp_common_pd_definitions.h"

StaticDnsCache::StaticDnsCache(std::string filename) :
  _dns_config_file(filename)
{
  reload_static_records();
}

StaticDnsCache::~StaticDnsCache()
{
  for (const std::pair<std::string, std::vector<DnsRRecord*>>& entry : _static_records)
  {
    for (DnsRRecord *record : entry.second)
    {
      delete record;
    }
  }
  _static_records.clear();
}

void StaticDnsCache::reload_static_records()
{
  if (_dns_config_file == "")
  {
    return;
  }

  std::ifstream fs(_dns_config_file.c_str());

  if (!fs)
  {
    TRC_ERROR("DNS config file %s missing", _dns_config_file.c_str());
    CL_DNS_FILE_MISSING.log();
    return;
  }

  TRC_STATUS("Loading static DNS records from %s",
             _dns_config_file.c_str());

  std::string dns_config((std::istreambuf_iterator<char>(fs)),
                         std::istreambuf_iterator<char>());

  rapidjson::Document doc;
  doc.Parse<0>(dns_config.c_str());

  if (doc.HasParseError())
  {
    TRC_ERROR("Unable to parse dns config file: %s\nError: %s",
              dns_config.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_DNS_FILE_MALFORMED.log();
    return;
  }

  try
  {
    std::map<std::string, std::vector<DnsRRecord*>> static_records;

    JSON_ASSERT_CONTAINS(doc, "hostnames");
    JSON_ASSERT_ARRAY(doc["hostnames"]);
    rapidjson::Value& hosts_arr = doc["hostnames"];

    for (rapidjson::Value::ConstValueIterator hosts_it = hosts_arr.Begin();
         hosts_it != hosts_arr.End();
         ++hosts_it)
    {
      try
      {
        std::string hostname;
        JSON_GET_STRING_MEMBER(*hosts_it, "name", hostname);

        if (static_records.find(hostname) != static_records.end())
        {
          TRC_ERROR("Duplicate entry found for hostname %s", hostname.c_str());
          CL_DNS_FILE_DUPLICATES.log();
          continue;
        }

        JSON_ASSERT_CONTAINS(*hosts_it, "records");
        JSON_ASSERT_ARRAY((*hosts_it)["records"]);
        const rapidjson::Value& records_arr = (*hosts_it)["records"];

        std::vector<DnsRRecord*> records = std::vector<DnsRRecord*>();

        // We only allow one record of each type per hostname.
        bool have_cname = false;
        bool have_a_record = false;

        for (rapidjson::Value::ConstValueIterator records_it = records_arr.Begin();
             records_it != records_arr.End();
             ++records_it)
        {
          try
          {
            // Each record object must have an "rrtype" member
            std::string type;
            JSON_GET_STRING_MEMBER(*records_it, "rrtype", type);

            // Currently we only support CNAME and A records.
            if (type == "CNAME")
            {
              // CNAME records should have a target, but only one per hostname is allowed
              if (!have_cname)
              {
                std::string target;
                JSON_GET_STRING_MEMBER(*records_it, "target", target);
                TRC_VERBOSE("Found CNAME record for hostname %s", hostname.c_str());
                DnsCNAMERecord* record = new DnsCNAMERecord(hostname, 0, target);
                records.push_back(record);
                have_cname = true;
              }
              else
              {
                TRC_ERROR("Multiple CNAME entries found for hostname %s", hostname.c_str());
                CL_DNS_FILE_DUPLICATES.log();
              }
            }
            else if (type == "A")
            {
              if (!have_a_record)
              {
                JSON_ASSERT_CONTAINS(*records_it, "targets");
                JSON_ASSERT_ARRAY((*records_it)["targets"]);
                const rapidjson::Value& targets_arr = (*records_it)["targets"];
                TRC_VERBOSE("Found A record for hostname %s", hostname.c_str());

                for (rapidjson::Value::ConstValueIterator targets_it = targets_arr.Begin();
                    targets_it != targets_arr.End();
                    ++targets_it)
                {
                  JSON_ASSERT_STRING(*targets_it);
                  std::string target = targets_it->GetString();
                  struct in_addr address;
                  inet_pton(AF_INET, target.c_str(), &address);
                  DnsARecord* record = new DnsARecord(hostname, 0, address);
                  records.push_back(record);
                }

                have_a_record = true;
              }
              else
              {
                TRC_ERROR("Multiple A records found for hostname %s", hostname.c_str());
              }
            }
            else
            {
              TRC_ERROR("Found unsupported record type: %s", type.c_str());
              CL_DNS_FILE_BAD_ENTRY.log();
            }
          }
          catch (JsonFormatError err)
          {
            TRC_ERROR("Bad DNS record specified for hostname %s in DNS config file %s",
                      hostname.c_str(),
                      _dns_config_file.c_str());
            CL_DNS_FILE_BAD_ENTRY.log();
          }
        }

        static_records.insert(std::make_pair(hostname, records));
      }
      catch (JsonFormatError err)
      {
        TRC_ERROR("Malformed entry in DNS config file %s. Each entry must have "
                  "a \"name\" and \"records\" member",
                  _dns_config_file.c_str());
        CL_DNS_FILE_BAD_ENTRY.log();
      }
    }

    // Now swap out the old _static_records for the new one.
    std::swap(_static_records, static_records);
    TRC_STATUS("Loaded %d static DNS records from %s",
               _static_records.size(),
               _dns_config_file.c_str());

    // Finally, clean up the now unused records
    for (const std::pair<std::string, std::vector<DnsRRecord*>>& entry : static_records)
    {
      for (DnsRRecord* record : entry.second)
      {
        delete record;
      }
    }
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Error parsing dns config file %s.", _dns_config_file.c_str());
    CL_DNS_FILE_MALFORMED.log();
  }
}

DnsResult StaticDnsCache::get_static_dns_records(std::string domain,
                                                 int dns_type)
{
  std::vector<DnsRRecord*> found_records;
  std::map<std::string, std::vector<DnsRRecord*>>::const_iterator map_iter =
                                                                      _static_records.find(domain);
  if (map_iter != _static_records.end())
  {
    TRC_DEBUG("Found records for domain %s", domain.c_str());
    for (DnsRRecord* record : map_iter->second)
    {
      if (record->rrtype() != dns_type)
      {
        // These are not the DNS records you are looking for.
        continue;
      }

      // Currently only A and CNAME records are supported.
      if (record->rrtype() == ns_t_a)
      {
        DnsARecord* a_record = (DnsARecord*)record;
        TRC_VERBOSE("Static A record found: %s -> %s",
                    domain.c_str(),
                    a_record->to_string().c_str());
        found_records.push_back(a_record);
      }
      else if (record->rrtype() == ns_t_cname)
      {
        DnsCNAMERecord* cname_record = (DnsCNAMERecord*)record;
        TRC_VERBOSE("Static CNAME record found: %s -> %s",
                    domain.c_str(),
                    cname_record->target().c_str());
        found_records.push_back(cname_record);

        // There should only be one matching CNAME record.
        break;
      }
    }
  }
  else
  {
    TRC_DEBUG("No static records found matching %s", domain.c_str());
  }

  return DnsResult(domain, dns_type, found_records, 0);
}

std::string StaticDnsCache::get_canonical_name(std::string domain)
{
  DnsResult static_result = get_static_dns_records(domain, ns_t_cname);
  if (!static_result.records().empty())
  {
    DnsCNAMERecord *cname_record = (DnsCNAMERecord*)static_result.records().front();
    TRC_VERBOSE("Found matching CNAME record in static cache", cname_record->target().c_str());
    return cname_record->target();
  }
  else
  {

    TRC_VERBOSE("No matching CNAME record found in static cache");
    return domain;
  }
}

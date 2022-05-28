#include <atomic>
#include <vector>
#include <map>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "snmp_ip_count_table.h"
#include "snmp_internal/snmp_table.h"
#include "snmp_internal/snmp_includes.h"
#include "logger.h"

namespace SNMP
{

IPCountRow::IPCountRow(struct in_addr addr) : IPRow(addr), _count(0) {};

IPCountRow::IPCountRow(struct in6_addr addr) : IPRow(addr), _count(0) {};

ColumnData IPCountRow::get_columns()
{
  ColumnData ret;
  ret[1] = Value::integer(_addr_type);
  ret[2] = Value(ASN_OCTET_STR, (unsigned char*)&_addr, _addr_len);
  ret[3] = Value::uint(_count);
  return ret;
}

class IPCountTableImpl: public ManagedTable<IPCountRow, std::string>, public IPCountTable
{
public:
  IPCountTableImpl(std::string name,
                   std::string tbl_oid):
    ManagedTable<IPCountRow, std::string>(name,
                                          tbl_oid,
                                          3,
                                          3, 
                                          { ASN_INTEGER, ASN_OCTET_STR }) 
  {}

  IPCountRow* new_row(std::string ip)
  {
    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1)
    {
      return new IPCountRow(v4);
    }
    else if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1)
    {
      return new IPCountRow(v6);
    }
    else
    {
      TRC_ERROR("Could not parse %s as an IPv4 or IPv6 address", ip.c_str());
      return NULL;
    }
  }

  IPCountRow* get(std::string key)
  {
    pthread_mutex_lock(&_map_lock);
    IPCountRow* ret = ManagedTable<IPCountRow, std::string>::get(key);
    pthread_mutex_unlock(&_map_lock);
    return ret;
  };

  void add(std::string key)
  {
    pthread_mutex_lock(&_map_lock);
    ManagedTable<IPCountRow, std::string>::add(key);
    pthread_mutex_unlock(&_map_lock);
  };

  void remove(std::string key)
  {
    pthread_mutex_lock(&_map_lock);
    ManagedTable<IPCountRow, std::string>::remove(key);
    pthread_mutex_unlock(&_map_lock);
  };

};

IPCountTable* IPCountTable::create(std::string name, std::string oid)
{
  return new IPCountTableImpl(name, oid);
}

}

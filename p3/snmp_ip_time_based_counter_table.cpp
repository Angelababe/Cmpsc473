#include <atomic>
#include "snmp_internal/snmp_table.h"
#include "snmp_internal/snmp_includes.h"

#include "current_and_previous.h"
#include "snmp_types.h"
#include "snmp_ip_row.h"
#include "snmp_ip_time_based_counter_table.h"

namespace SNMP
{
class IPTimeBasedCounterTableImpl;
class IPTimeBasedCounterRow : public IPRow
{
public:
  IPTimeBasedCounterRow(struct in_addr addr,
                         const std::string& ip_str,
                         TimePeriodIndexes time_period,
                         IPTimeBasedCounterTableImpl* table) :
    IPRow(addr), _table(table), _ip_str(ip_str), _time_period(time_period)
  {
    netsnmp_tdata_row_add_index(_row,
                                ASN_INTEGER,
                                &_time_period,
                                sizeof(int));
  }
  IPTimeBasedCounterRow(struct in6_addr addr,
                         const std::string& ip_str,
                         TimePeriodIndexes time_period,
                         IPTimeBasedCounterTableImpl* table) :
    IPRow(addr), _table(table), _ip_str(ip_str), _time_period(time_period)
  {
    netsnmp_tdata_row_add_index(_row,
                                ASN_INTEGER,
                                &_time_period,
                                sizeof(int));
  }

  virtual ~IPTimeBasedCounterRow() {}
  ColumnData get_columns();

private:
  IPTimeBasedCounterTableImpl* _table;
  std::string _ip_str;
  TimePeriodIndexes _time_period;
};

typedef std::pair<std::string, TimePeriodIndexes> IPTimeBasedCounterIndex;

class IPTimeBasedCounterTableImpl : public IPTimeBasedCounterTable,
                                     public ManagedTable<IPTimeBasedCounterRow, IPTimeBasedCounterIndex>
{
public:
  IPTimeBasedCounterTableImpl(std::string name, std::string tbl_oid) :
    ManagedTable<IPTimeBasedCounterRow, IPTimeBasedCounterIndex>(
      name, tbl_oid, 4, 4, { ASN_INTEGER, ASN_OCTET_STR, ASN_INTEGER })
  {
    pthread_rwlock_init(&_table_lock, NULL);
  }

  ~IPTimeBasedCounterTableImpl()
  {
    pthread_rwlock_destroy(&_table_lock);

    for(std::map<std::string, IPEntry*>::iterator it = _counters_by_ip.begin();
        it != _counters_by_ip.end();
        ++it)
    {
      delete it->second; it->second = NULL;
    }
  }

  void add_ip(const std::string& ip)
  {
    pthread_rwlock_wrlock(&_table_lock);

    std::map<std::string, uint32_t>::iterator ref_entry = _ref_count_by_ip.find(ip);

    if (ref_entry == _ref_count_by_ip.end())
    {
      _ref_count_by_ip[ip] = 1;

      std::map<std::string, IPEntry*>::iterator entry = _counters_by_ip.find(ip);

      if (entry == _counters_by_ip.end())
      {
        TRC_DEBUG("Adding IP rows for: %s", ip.c_str());

        _counters_by_ip[ip] = new IPEntry();
        add(std::make_pair(ip, TimePeriodIndexes::scopePrevious5SecondPeriod));
        add(std::make_pair(ip, TimePeriodIndexes::scopeCurrent5MinutePeriod));
        add(std::make_pair(ip, TimePeriodIndexes::scopePrevious5MinutePeriod));
      }
      else
      {
        TRC_ERROR("Entry for %s doesn't exist in reference table, but does exist in count table",
                  ip.c_str());
      }
    }
    else
    {
      ref_entry->second++;
    }

    pthread_rwlock_unlock(&_table_lock);
  }

  void remove_ip(const std::string& ip)
  {
    pthread_rwlock_wrlock(&_table_lock);

    std::map<std::string, uint32_t>::iterator ref_entry = _ref_count_by_ip.find(ip);

    if (ref_entry == _ref_count_by_ip.end())
    {
      TRC_ERROR("Attempted to delete row for %s which isn't in the reference table",
                ip.c_str());
    }
    else
    {
      ref_entry->second --;
      if (ref_entry->second == 0)
      {
        std::map<std::string, IPEntry*>::iterator entry = _counters_by_ip.find(ip);

        if (entry != _counters_by_ip.end())
        {
          TRC_DEBUG("Removing IP rows for %s", ip.c_str());

          delete entry->second; entry->second = NULL;
          _counters_by_ip.erase(entry);
          remove(std::make_pair(ip, TimePeriodIndexes::scopePrevious5SecondPeriod));
          remove(std::make_pair(ip, TimePeriodIndexes::scopeCurrent5MinutePeriod));
          remove(std::make_pair(ip, TimePeriodIndexes::scopePrevious5MinutePeriod));
        }
        else
        {
          TRC_ERROR("Entry for %s exists in reference table, but not the count table",
                    ip.c_str());
        }
      }
    }

    pthread_rwlock_unlock(&_table_lock);
  }

  void increment(const std::string& ip)
  {
    pthread_rwlock_rdlock(&_table_lock);

    std::map<std::string, IPEntry*>::iterator entry = _counters_by_ip.find(ip);
    if (entry != _counters_by_ip.end())
    {
      TRC_DEBUG("Incrementing counter for %s", ip.c_str());
      entry->second->five_sec.get_current()->counter++;
      entry->second->five_min.get_current()->counter++;
    }

    pthread_rwlock_unlock(&_table_lock);
  }

  uint32_t get_count(const std::string& ip, TimePeriodIndexes time_period)
  {
    TRC_DEBUG("Get count for IP: %s, time period: %d", ip.c_str(), time_period);

    uint32_t count = 0;
    pthread_rwlock_rdlock(&_table_lock);

    std::map<std::string, IPEntry*>::iterator entry = _counters_by_ip.find(ip);
    if (entry != _counters_by_ip.end())
    {
      switch (time_period)
      {
      case TimePeriodIndexes::scopePrevious5SecondPeriod:
        count = entry->second->five_sec.get_previous()->counter;
        break;

      case TimePeriodIndexes::scopeCurrent5MinutePeriod:
        count = entry->second->five_min.get_current()->counter;
        break;

      case TimePeriodIndexes::scopePrevious5MinutePeriod:
        count = entry->second->five_min.get_previous()->counter;
        break;

      default:
        // LCOV_EXCL_START
        TRC_ERROR("Invalid time period requested: %d", time_period);
        count = 0;
        break;
      }
    }

    pthread_rwlock_unlock(&_table_lock);

    TRC_DEBUG("Counter is %d", count);
    return count;
  }

private:

  IPTimeBasedCounterRow* new_row(IPTimeBasedCounterIndex index)
  {
    std::string& ip = index.first;
    TimePeriodIndexes time_period = index.second;
    TRC_DEBUG("Create new SNMP row for IP: %s, time period: %d", ip.c_str(), time_period);

    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1)
    {
      return new IPTimeBasedCounterRow(v4, ip, time_period, this);
    }
    else if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1)
    {
      return new IPTimeBasedCounterRow(v6, ip, time_period, this);
    }
    else
    {
      TRC_ERROR("Could not parse %s as an IPv4 or IPv6 address", ip.c_str());
      return NULL;
    }
  }
  struct Counter
  {
    std::atomic_uint_fast32_t counter;

    void reset(uint64_t time_periodstart, Counter* previous = NULL)
    {
      counter = 0;
    }
  };
  struct IPEntry
  {
    IPEntry() : five_sec(5 * 1000), five_min(5 * 60 * 1000) {}
    CurrentAndPrevious<Counter> five_sec;
    CurrentAndPrevious<Counter> five_min;
  };
  std::map<std::string, IPEntry*> _counters_by_ip;
  std::map<std::string, uint32_t> _ref_count_by_ip;

  pthread_rwlock_t _table_lock;
};


IPTimeBasedCounterTable* IPTimeBasedCounterTable::create(std::string name,
                                                         std::string oid)
{
  return new IPTimeBasedCounterTableImpl(name, oid);
}


ColumnData IPTimeBasedCounterRow::get_columns()
{
  TRC_DEBUG("Columns requested for row: IP: %s time period: %d", _ip_str.c_str(), _time_period);

  ColumnData ret;
  // IP address
  ret[1] = Value::integer(_addr_type);
  ret[2] = Value(ASN_OCTET_STR, (unsigned char*)&_addr, _addr_len);
  // Time period
  ret[3] = Value::integer(_time_period);
  // Count
  ret[4] = Value::uint(_table->get_count(_ip_str, _time_period));
  return ret;
}

}

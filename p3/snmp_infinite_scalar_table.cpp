#include <atomic>
#include <string>
#include <algorithm>
#include <memory>
#include <mutex>

#include "snmp_infinite_scalar_table.h"
#include "snmp_row.h"
#include "snmp_infinite_base_table.h"

#include "log.h"
#include "logger.h"


namespace SNMP
{
  class InfiniteScalarTableImpl : public InfiniteScalarTable, public InfiniteBaseTable
  {
  public:
    InfiniteScalarTableImpl(std::string name,
                            std::string tbl_oid):
    InfiniteBaseTable(name, tbl_oid, max_row, max_column){}

    virtual ~InfiniteScalarTableImpl(){};
    
    void increment(std::string tag, uint32_t count)
    {
      _mutex.lock();
      _scalar_counters[tag] += count;
      _mutex.unlock();
    }

    void decrement(std::string tag, uint32_t count)
    {
      _mutex.lock();
      if (_scalar_counters[tag] > count)
        {
          _scalar_counters[tag] -= count;
        }
      else
        {
          _scalar_counters[tag] = 0;
        }
      _mutex.unlock();
    }

  protected:
    static const uint32_t max_row = 1;
    static const uint32_t max_column = 2;
    std::map<std::string, uint32_t> _scalar_counters;
    std::mutex _mutex;

  private:
    Value get_value(std::string tag,
                    uint32_t column,
                    uint32_t row,
                    timespec now)
    {
      Value result = Value::uint(0);

      if (column !=2 && row != 1)
      {
        TRC_DEBUG("Internal MIB error - column %d is out of bounds",
                  column);
        return Value::uint(0);
      }

      _mutex.lock();
      if (_scalar_counters.count(tag) > 0)
      {
        result = Value::uint(_scalar_counters[tag]);
      }
      _mutex.unlock();

      TRC_DEBUG("Got value %u for tag %s cell (%d, %d)",
                *result.value, tag.c_str(), row, column);

      return result;
    }
  };

  InfiniteScalarTable* InfiniteScalarTable::create(std::string name, std::string oid)
  {
    return new InfiniteScalarTableImpl(name, oid);
  };
}

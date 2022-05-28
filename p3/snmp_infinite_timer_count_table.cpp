#include <atomic>
#include <string>
#include <algorithm>
#include <memory>
#include "snmp_statistics_structures.h"
#include "snmp_infinite_timer_count_table.h"
#include "timer_counter.h"
#include "snmp_row.h"
#include "snmp_infinite_base_table.h"
#include "log.h"
#include "logger.h"

namespace SNMP
{
  class InfiniteTimerCountTableImpl : public InfiniteTimerCountTable, public InfiniteBaseTable
  {
  public:
    InfiniteTimerCountTableImpl(std::string name, 
                                std::string tbl_oid) : 
                                InfiniteBaseTable(name, tbl_oid, max_row, max_column){}

    virtual ~InfiniteTimerCountTableImpl(){};
    
    void increment(std::string tag, uint32_t count)
    {
      _timer_counters[tag].increment(count);
    }

    void decrement(std::string tag, uint32_t count)
    {
      _timer_counters[tag].decrement(count);
    }

  protected:
    static const uint32_t max_row = 3;
    static const uint32_t max_column = 5;
    std::map<std::string, TimerCounter> _timer_counters;

  private:
    Value get_value(std::string tag,
                    uint32_t column,
                    uint32_t row,
                    timespec now)
    {
      SimpleStatistics stats;
      Value result = Value::uint(0);
      _timer_counters[tag].get_statistics(row, now, &stats);
      result = read_column(&stats, tag, column, now);
      TRC_DEBUG("Got value %u for tag %s cell (%d, %d)",
                *result.value, tag.c_str(), row, column);

      return result;
    }

    Value read_column(SimpleStatistics* data,
                       std::string tag,
                       uint32_t column,
                       timespec now)
    {
      switch (column)
      {
        case 2:
          return Value::uint(data->average);
        case 3:
          return Value::uint(data->variance);
        case 4:
          return Value::uint(data->hwm);
        case 5:
          return Value::uint(data->lwm);
        default:
          TRC_DEBUG("Internal MIB error - column %d is out of bounds",
                    column);
          return Value::uint(0);
      }
    }

  };

  InfiniteTimerCountTable* InfiniteTimerCountTable::create(std::string name, std::string oid)
  {
    return new InfiniteTimerCountTableImpl(name, oid);
  };
}

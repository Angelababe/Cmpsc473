#include <atomic>
#include "snmp_counter_table.h"
#include "snmp_counter_by_scope_table.h"
#include "snmp_statistics_structures.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_time_period_table.h"
#include "snmp_internal/snmp_time_period_and_scope_table.h"
#include "logger.h"

namespace SNMP
{
class CounterByScopeRow: public TimeAndScopeBasedRow<SingleCount>
{
public:
  CounterByScopeRow(int index, std::string scope_index, View* view):
    TimeAndScopeBasedRow<SingleCount>(index, scope_index, view) {};
  ColumnData get_columns()
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME_COARSE, &now);

    SingleCount accumulated = *(this->_view->get_data(now));

     ColumnData ret;
    ret[3] = Value::uint(accumulated.count);
    return ret;
  }
};

class CounterTableByScopeImpl: public ManagedTable<CounterByScopeRow, int>, public CounterByScopeTable
{
public:
  CounterTableByScopeImpl(std::string name,
                          std::string tbl_oid):
    ManagedTable<CounterByScopeRow, int>(name,
                                         tbl_oid,
                                         3,
                                         3, 
                                         { ASN_INTEGER , ASN_OCTET_STR }), 
    five_second(5000),
    five_minute(300000)
  {
    n = 0;

    this->add(n++, new_row(scopePrevious5SecondPeriod));
    this->add(n++, new_row(scopeCurrent5MinutePeriod));
    this->add(n++, new_row(scopePrevious5MinutePeriod));
  }

  void increment()
  {
    five_second.get_current()->count++;
    five_minute.get_current()->count++;
  }

private:
  CounterByScopeRow* new_row(int index)
  {
    CounterByScopeRow::View* view = NULL;
    switch (index)
    {
      case TimePeriodIndexes::scopePrevious5SecondPeriod:
        view = new CounterByScopeRow::PreviousView(&five_second);
        break;
      case TimePeriodIndexes::scopeCurrent5MinutePeriod:
        view = new CounterByScopeRow::CurrentView(&five_minute);
        break;
      case TimePeriodIndexes::scopePrevious5MinutePeriod:
        view = new CounterByScopeRow::PreviousView(&five_minute);
        break;
    }
    return new CounterByScopeRow(index, "node", view);
  }

  int n;

  CurrentAndPrevious<SingleCount> five_second;
  CurrentAndPrevious<SingleCount> five_minute;
};

CounterByScopeTable* CounterByScopeTable::create(std::string name, std::string oid)
{
  return new CounterTableByScopeImpl(name, oid);
}

}

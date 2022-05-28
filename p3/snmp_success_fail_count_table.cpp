#include <atomic>
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_time_period_table.h"
#include "snmp_success_fail_count_table.h"
#include "snmp_statistics_structures.h"
#include "logger.h"

namespace SNMP
{
class SuccessFailCountRow: public TimeBasedRow<SuccessFailCount>
{
public:
  SuccessFailCountRow(int index, View* view):
    TimeBasedRow<SuccessFailCount>(index, view) {};
  ColumnData get_columns()
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME_COARSE, &now);

    SuccessFailCount* counts = _view->get_data(now);
    uint_fast32_t attempts = counts->attempts.load();
    uint_fast32_t successes = counts->successes.load();
    uint_fast32_t failures = counts->failures.load();
    uint_fast32_t success_percent_in_ten_thousands = 0;
    if (attempts == uint_fast32_t(0))
    {
      success_percent_in_ten_thousands = 100 * 10000;
    }
    else if (successes > 0)
    {

      success_percent_in_ten_thousands = (successes * 100 * 10000) / (successes + failures);
    }

    ColumnData ret;
    ret[1] = Value::integer(_index);
    ret[2] = Value::uint(attempts);
    ret[3] = Value::uint(successes);
    ret[4] = Value::uint(failures);
    ret[5] = Value::uint(success_percent_in_ten_thousands);
    return ret;
  }
};

class SuccessFailCountTableImpl: public ManagedTable<SuccessFailCountRow, int>, public SuccessFailCountTable
{
public:
  SuccessFailCountTableImpl(std::string name,
                            std::string tbl_oid):
    ManagedTable<SuccessFailCountRow, int>(name,
                                           tbl_oid,
                                           2,
                                           5,
                                           { ASN_INTEGER }), 
    five_second(5000),
    five_minute(300000)
  {
    add(TimePeriodIndexes::scopePrevious5SecondPeriod);
    add(TimePeriodIndexes::scopeCurrent5MinutePeriod);
    add(TimePeriodIndexes::scopePrevious5MinutePeriod);
  }

  void increment_attempts()
  {
    five_second.get_current()->attempts++;
    five_minute.get_current()->attempts++;
  }

  void increment_successes()
  {
    five_second.get_current()->successes++;
    five_minute.get_current()->successes++;
  }

  void increment_failures()
  {
    five_second.get_current()->failures++;
    five_minute.get_current()->failures++;
  }

private:
  SuccessFailCountRow* new_row(int index)
  {
    SuccessFailCountRow::View* view = NULL;
    switch (index)
    {
      case TimePeriodIndexes::scopePrevious5SecondPeriod:
        view = new SuccessFailCountRow::PreviousView(&five_second);
        break;
      case TimePeriodIndexes::scopeCurrent5MinutePeriod:
        view = new SuccessFailCountRow::CurrentView(&five_minute);
        break;
      case TimePeriodIndexes::scopePrevious5MinutePeriod:
        view = new SuccessFailCountRow::PreviousView(&five_minute);
        break;
    }
    return new SuccessFailCountRow(index, view);
  }

  CurrentAndPrevious<SuccessFailCount> five_second;
  CurrentAndPrevious<SuccessFailCount> five_minute;
};

SuccessFailCountTable* SuccessFailCountTable::create(std::string name, std::string oid)
{
  return new SuccessFailCountTableImpl(name, oid);
}

}

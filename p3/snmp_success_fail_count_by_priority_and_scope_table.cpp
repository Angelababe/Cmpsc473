#include <atomic>
#include "snmp_success_fail_count_by_priority_and_scope_table.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_counts_by_other_type_and_scope_table.h"
#include "snmp_statistics_structures.h"
#include "sip_event_priority.h"
#include "logger.h"

namespace SNMP
{
class SuccessFailCountByPriorityAndScopeRow: public TimeOtherTypeAndScopeBasedRow<SuccessFailCount>
{
public:
  SuccessFailCountByPriorityAndScopeRow(int time_index, int type_index, View* view):
    TimeOtherTypeAndScopeBasedRow<SuccessFailCount>(time_index, type_index, "node", view) {};
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
    ret[4] = Value::uint(attempts);
    ret[5] = Value::uint(successes);
    ret[6] = Value::uint(failures);
    ret[7] = Value::uint(success_percent_in_ten_thousands);
    return ret;
  }
  static int get_count_size() { return 4; }
};

static std::vector<int> priorities =
{
  SIPEventPriorityLevel::NORMAL_PRIORITY,
  SIPEventPriorityLevel::HIGH_PRIORITY_1,
  SIPEventPriorityLevel::HIGH_PRIORITY_2,
  SIPEventPriorityLevel::HIGH_PRIORITY_3,
  SIPEventPriorityLevel::HIGH_PRIORITY_4,
  SIPEventPriorityLevel::HIGH_PRIORITY_5,
  SIPEventPriorityLevel::HIGH_PRIORITY_6,
  SIPEventPriorityLevel::HIGH_PRIORITY_7,
  SIPEventPriorityLevel::HIGH_PRIORITY_8,
  SIPEventPriorityLevel::HIGH_PRIORITY_9,
  SIPEventPriorityLevel::HIGH_PRIORITY_10,
  SIPEventPriorityLevel::HIGH_PRIORITY_11,
  SIPEventPriorityLevel::HIGH_PRIORITY_12,
  SIPEventPriorityLevel::HIGH_PRIORITY_13,
  SIPEventPriorityLevel::HIGH_PRIORITY_14,
  SIPEventPriorityLevel::HIGH_PRIORITY_15
};

class SuccessFailCountByPriorityAndScopeTableImpl: public CountsByOtherTypeAndScopeTableImpl<SuccessFailCountByPriorityAndScopeRow, SuccessFailCount>,
  public SuccessFailCountByPriorityAndScopeTable
{
public:
  SuccessFailCountByPriorityAndScopeTableImpl(std::string name,
                                              std::string tbl_oid):
    CountsByOtherTypeAndScopeTableImpl<SuccessFailCountByPriorityAndScopeRow,
                                       SuccessFailCount>(name,
                                                         tbl_oid,
                                                         priorities)
  {}

  void increment_attempts(int priority)
  {
    five_second[priority]->get_current()->attempts++;
    five_minute[priority]->get_current()->attempts++;
  }

  void increment_successes(int priority)
  {
    five_second[priority]->get_current()->successes++;
    five_minute[priority]->get_current()->successes++;
  }

  void increment_failures(int priority)
  {
    five_second[priority]->get_current()->failures++;
    five_minute[priority]->get_current()->failures++;
  }
};

SuccessFailCountByPriorityAndScopeTable* SuccessFailCountByPriorityAndScopeTable::create(std::string name,
                                                                                         std::string oid)
{
  return new SuccessFailCountByPriorityAndScopeTableImpl(name, oid);
}

}

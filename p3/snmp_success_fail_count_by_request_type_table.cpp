#include <atomic>
#include "snmp_success_fail_count_by_request_type_table.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_counts_by_other_type_table.h"
#include "snmp_statistics_structures.h"
#include "snmp_sip_request_types.h"
#include "logger.h"

namespace SNMP
{
class SuccessFailCountByRequestTypeRow: public TimeAndOtherTypeBasedRow<SuccessFailCount>
{
public:
  SuccessFailCountByRequestTypeRow(int time_index, int type_index, View* view):
    TimeAndOtherTypeBasedRow<SuccessFailCount>(time_index, type_index, view) {};
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
    ret[1] = Value::integer(this->_index);
    ret[2] = Value::integer(this->_type_index);
    ret[3] = Value::uint(attempts);
    ret[4] = Value::uint(successes);
    ret[5] = Value::uint(failures);
    ret[6] = Value::uint(success_percent_in_ten_thousands);
    return ret;
  }
  static int get_count_size() { return 4; }
};

static std::vector<int> request_types =
{
  SIPRequestTypes::INVITE,
  SIPRequestTypes::ACK,
  SIPRequestTypes::BYE,
  SIPRequestTypes::CANCEL,
  SIPRequestTypes::OPTIONS,
  SIPRequestTypes::REGISTER,
  SIPRequestTypes::PRACK,
  SIPRequestTypes::SUBSCRIBE,
  SIPRequestTypes::NOTIFY,
  SIPRequestTypes::PUBLISH,
  SIPRequestTypes::INFO,
  SIPRequestTypes::REFER,
  SIPRequestTypes::MESSAGE,
  SIPRequestTypes::UPDATE,
  SIPRequestTypes::OTHER
};

class SuccessFailCountByRequestTypeTableImpl: public CountsByOtherTypeTableImpl<SuccessFailCountByRequestTypeRow, SuccessFailCount>,
  public SuccessFailCountByRequestTypeTable
{
public:
  SuccessFailCountByRequestTypeTableImpl(std::string name,
                                         std::string tbl_oid):
    CountsByOtherTypeTableImpl<SuccessFailCountByRequestTypeRow,
                               SuccessFailCount>(name,
                                                 tbl_oid,
                                                 request_types)
  {}

  void increment_attempts(SIPRequestTypes type)
  {
    five_second[type]->get_current()->attempts++;
    five_minute[type]->get_current()->attempts++;
  }

  void increment_successes(SIPRequestTypes type)
  {
    five_second[type]->get_current()->successes++;
    five_minute[type]->get_current()->successes++;
  }

  void increment_failures(SIPRequestTypes type)
  {
    five_second[type]->get_current()->failures++;
    five_minute[type]->get_current()->failures++;
  }
};

SuccessFailCountByRequestTypeTable* SuccessFailCountByRequestTypeTable::create(std::string name,
                                                                               std::string oid)
{
  return new SuccessFailCountByRequestTypeTableImpl(name, oid);
}

}

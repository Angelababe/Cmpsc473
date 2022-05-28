#include <atomic>
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_time_period_and_string_table.h"
#include "snmp_time_and_string_based_event_table.h"
#include "event_statistic_accumulator.h"
#include <vector>
#include "log.h"

namespace SNMP
{

class TimeAndStringBasedEventRow: public TimeAndStringBasedRow<EventStatisticAccumulator>
{
public:
  TimeAndStringBasedEventRow(int time_index, std::string str_index, View* view):
    TimeAndStringBasedRow<EventStatisticAccumulator>(time_index, str_index, view) {};

  ColumnData get_columns()
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME_COARSE, &now);

    EventStatistics statistics;
    EventStatisticAccumulator* accumulated = _view->get_data(now);
    accumulated->get_stats(statistics);

    ColumnData ret;
    ret[1] = Value::integer(this->_index);
    ret[2] = Value(ASN_OCTET_STR,
                   (unsigned char*)(this->_string_index.c_str()),
                   this->_string_index.size());
    ret[3] = Value::uint(statistics.mean);
    ret[4] = Value::uint(statistics.variance);
    ret[5] = Value::uint(statistics.hwm);
    ret[6] = Value::uint(statistics.lwm);
    ret[7] = Value::uint(statistics.count);
    return ret;
  }
};

class TimeAndStringBasedEventTableImpl: public ManagedTable<TimeAndStringBasedEventRow, int>, public TimeAndStringBasedEventTable
{
public:
  TimeAndStringBasedEventTableImpl(std::string name,
                                   std::string tbl_oid):
    ManagedTable<TimeAndStringBasedEventRow, int>(name,
                                                  tbl_oid,
                                                  3,
                                                  7,
                                                  { ASN_INTEGER , ASN_OCTET_STR })
  {
    TRC_INFO("Created table with name %s, OID %s", name.c_str(), tbl_oid.c_str());
    _table_rows = 0;

    pthread_rwlock_init(&_table_lock, NULL);
  }
  void create_and_add_rows(std::string string_index)
  {
    pthread_rwlock_wrlock(&_table_lock);

    if (_five_second.count(string_index) != 0)
    {
      TRC_DEBUG("Tried to add new rows but another thread beat us to it");
      pthread_rwlock_unlock(&_table_lock);
      return;
    }

    _five_second[string_index] = new CurrentAndPrevious<EventStatisticAccumulator>(5000);
    _five_minute[string_index] = new CurrentAndPrevious<EventStatisticAccumulator>(300000);

    this->add(_table_rows++, new TimeAndStringBasedEventRow(TimePeriodIndexes::scopePrevious5SecondPeriod,
                                    string_index,
                                    new TimeAndStringBasedEventRow::PreviousView((_five_second)[string_index])));
    this->add(_table_rows++, new TimeAndStringBasedEventRow(TimePeriodIndexes::scopeCurrent5MinutePeriod,
                                    string_index,
                                    new TimeAndStringBasedEventRow::CurrentView((_five_minute)[string_index])));
    this->add(_table_rows++, new TimeAndStringBasedEventRow(TimePeriodIndexes::scopePrevious5MinutePeriod,
                                    string_index,
                                    new TimeAndStringBasedEventRow::PreviousView((_five_minute)[string_index])));

    pthread_rwlock_unlock(&_table_lock);
  }

  void accumulate(std::string string_index, uint32_t sample)
  {
    bool rows_exist = false;

    pthread_rwlock_rdlock(&_table_lock);
    rows_exist = (_five_second.count(string_index) != 0);
    pthread_rwlock_unlock(&_table_lock);

    if (!rows_exist)
    {
      TRC_DEBUG("Create new rows for %s", string_index.c_str());
      create_and_add_rows(string_index);
    }
    _five_second[string_index]->get_current()->accumulate(sample);
    _five_minute[string_index]->get_current()->accumulate(sample);
  }

  ~TimeAndStringBasedEventTableImpl()
  {
    TRC_INFO("Destroying table with name %s", _name.c_str());

    pthread_rwlock_destroy(&_table_lock);

    for (auto& kv : _five_second) {  delete kv.second; }
    for (auto& kv : _five_minute) {  delete kv.second; }
  }
private:

  TimeAndStringBasedEventRow* new_row(int indexes) { return NULL;};

  int _table_rows;

  pthread_rwlock_t _table_lock;
  std::map<std::string, CurrentAndPrevious<EventStatisticAccumulator>*> _five_second;
  std::map<std::string, CurrentAndPrevious<EventStatisticAccumulator>*> _five_minute;
};

TimeAndStringBasedEventTable* TimeAndStringBasedEventTable::create(std::string name,
                                       std::string oid)
{
  return new TimeAndStringBasedEventTableImpl(name, oid);
}

}

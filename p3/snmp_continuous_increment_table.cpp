#include <atomic>
#include "snmp_statistics_structures.h"
#include "snmp_internal/snmp_time_period_table.h"
#include "snmp_continuous_increment_table.h"
#include "limits.h"

namespace SNMP
{

class ContinuousAccumulatorRow: public TimeBasedRow<ContinuousStatistics>
{
public:
  ContinuousAccumulatorRow(int index, View* view): TimeBasedRow<ContinuousStatistics>(index, view) {};
  ColumnData get_columns();
};

class ContinuousIncrementTableImpl: public ManagedTable<ContinuousAccumulatorRow, int>,
                                    public ContinuousIncrementTable
{
public:
  ContinuousIncrementTableImpl(std::string name,
                               std::string tbl_oid):
                               ManagedTable<ContinuousAccumulatorRow, int>
                                     (name,
                                      tbl_oid,
                                      2,
                                      6, 
                                      { ASN_INTEGER }), 
    five_second(5000),
    five_minute(300000)
  {
    add(TimePeriodIndexes::scopePrevious5SecondPeriod);
    add(TimePeriodIndexes::scopeCurrent5MinutePeriod);
    add(TimePeriodIndexes::scopePrevious5MinutePeriod);
  }

  void increment(uint32_t value)
  {
    count_internal(five_second, value, TRUE);
    count_internal(five_minute, value, TRUE);
  }

  void decrement(uint32_t value)
  {
    count_internal(five_second, value, FALSE);
    count_internal(five_minute, value, FALSE);
  }

private:
  ContinuousAccumulatorRow* new_row(int index)
  {
    ContinuousAccumulatorRow::View* view = NULL;
    switch (index)
    {
      case TimePeriodIndexes::scopePrevious5SecondPeriod:
        view = new ContinuousAccumulatorRow::PreviousView(&five_second);
        break;
      case TimePeriodIndexes::scopeCurrent5MinutePeriod:
        view = new ContinuousAccumulatorRow::CurrentView(&five_minute);
        break;
      case TimePeriodIndexes::scopePrevious5MinutePeriod:
        view = new ContinuousAccumulatorRow::PreviousView(&five_minute);
        break;
    }
    return new ContinuousAccumulatorRow(index, view);
  }

  void count_internal(CurrentAndPrevious<ContinuousStatistics>& data, uint32_t value_delta, bool increment_total)
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME_COARSE, &now);

    ContinuousStatistics* current_data = data.get_current(now);

    uint64_t current_value = current_data->current_value;
    uint64_t new_value;
    do
    {
      if (increment_total)
      {
        new_value = current_value + value_delta;
      }
      else
      {
        if (value_delta < current_value)
        {
          new_value = current_value - value_delta;
        }
        else
        {
          new_value = 0;
        }
      }
    } while (!current_data->current_value.compare_exchange_weak(current_value, new_value));

    accumulate_internal(current_data, current_value, new_value, now);
  }

  void accumulate_internal(ContinuousStatistics* current_data,
                           uint64_t current_value,
                           uint64_t sample,
                           const struct timespec& now)
  {
    current_data->count++;

    uint64_t time_since_last_update = ((now.tv_sec * 1000) + (now.tv_nsec / 1000000))
                                     - (current_data->time_last_update_ms.load());

    current_data->time_last_update_ms = (now.tv_sec * 1000) + (now.tv_nsec / 1000000);
    current_data->sum += current_value * time_since_last_update;
    current_data->sqsum += current_value * current_value * time_since_last_update;

    uint_fast64_t lwm = current_data->lwm.load();
    while ((sample < lwm) &&
           (!current_data->lwm.compare_exchange_weak(lwm, sample)))
    {
      
    }
    uint_fast64_t hwm = current_data->hwm.load();
    while ((sample > hwm) &&
           (!current_data->hwm.compare_exchange_weak(hwm, sample)))
    {
     
    }
  };

  CurrentAndPrevious<ContinuousStatistics> five_second;
  CurrentAndPrevious<ContinuousStatistics> five_minute;
};

ColumnData ContinuousAccumulatorRow::get_columns()
{
  struct timespec now;
  clock_gettime(CLOCK_REALTIME_COARSE, &now);

  ContinuousStatistics* accumulated = _view->get_data(now);
  uint32_t interval_ms = _view->get_interval_ms();

  uint_fast32_t count = accumulated->count.load();
  uint_fast32_t current_value = accumulated->current_value.load();

  uint_fast64_t avg = current_value;
  uint_fast64_t variance = 0;
  uint_fast32_t lwm = accumulated->lwm.load();
  if (lwm == ULONG_MAX)
  {
    lwm = 0;
  }
  uint_fast32_t hwm = accumulated->hwm.load();
  uint_fast64_t sum = accumulated->sum.load();
  uint_fast64_t sqsum = accumulated->sqsum.load();

  uint64_t time_now_ms = (now.tv_sec * 1000) + (now.tv_nsec / 1000000);

  uint64_t time_comes_first_ms;
  uint_fast64_t time_period_start_ms;
  uint64_t time_period_end_ms;
  uint_fast64_t time_last_update_ms = accumulated->time_last_update_ms.load();
  do
  {
    time_period_start_ms = accumulated->time_period_start_ms.load();

    time_period_end_ms = ((time_period_start_ms + interval_ms) / interval_ms) * interval_ms;

    time_comes_first_ms = std::min(time_period_end_ms, time_now_ms);
  } while (!accumulated->time_last_update_ms.compare_exchange_weak(time_last_update_ms, time_comes_first_ms));

  uint64_t time_since_last_update_ms = time_comes_first_ms - time_last_update_ms;
  uint64_t period_count = (time_comes_first_ms - time_period_start_ms);

  if (period_count > 0)
  {
    uint64_t new_sum;
    do
    {
      new_sum = sum + (time_since_last_update_ms * current_value);
    } while (!accumulated->sum.compare_exchange_weak(sum, new_sum));

    uint64_t new_sqsum;
    do
    {
      new_sqsum = sqsum + (time_since_last_update_ms * current_value * current_value);
    } while (!accumulated->sum.compare_exchange_weak(sqsum, new_sqsum));

    avg = new_sum / period_count;
    variance = ((new_sqsum * period_count) - (new_sum * new_sum)) / (period_count * period_count);
  }

  ColumnData ret;
  ret[1] = Value::integer(_index);
  ret[2] = Value::uint(avg);
  ret[3] = Value::uint(variance);
  ret[4] = Value::uint(hwm);
  ret[5] = Value::uint(lwm);
  ret[6] = Value::uint(count);
  return ret;
}

ContinuousIncrementTable* ContinuousIncrementTable::create(std::string name,
                                                           std::string oid)
{
  return new ContinuousIncrementTableImpl(name, oid);
}
}

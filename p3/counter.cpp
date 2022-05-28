#include <atomic>
#include <vector>
#include "counter.h"

void Counter::increment(void)
{
  _current._count++;
  
  refresh();
}

void Counter::refresh(bool force)
{

  uint_fast64_t timestamp_us = _current._timestamp_us.load();
  uint_fast64_t timestamp_us_now = get_timestamp_us();

  if ((force ||
      (timestamp_us_now >= timestamp_us + _target_period_us)) &&
      (_current._timestamp_us.compare_exchange_weak(timestamp_us, timestamp_us_now)))
  {
    read(timestamp_us_now - timestamp_us);
    refreshed();
  }
}


void Counter::reset()
{
 
  _current._timestamp_us.store(get_timestamp_us());
  _current._count.store(0);
  _last._count = 0;
}
void Counter::read(uint_fast64_t period_us)
{
  uint_fast64_t count = _current._count.exchange(0);
  _last._count = count ;
}
void StatisticCounter::refreshed()
{
  std::vector<std::string> values;
  values.push_back(std::to_string(get_count()));
  _statistic.report_change(values);
}

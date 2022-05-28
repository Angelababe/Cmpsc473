#include <atomic>
#include <vector>

#include "accumulator.h"

/// Accumulate a sample into our results.
void Accumulator::accumulate(unsigned long sample)
{
  // Update the basic counters and samples.
  _current._n++;
  _current._sigma += sample;
  _current._sigma_squared += sample * sample;
  uint_fast64_t lwm = _current._lwm.load();
  while ((sample < lwm) &&
	 (!_current._lwm.compare_exchange_weak(lwm, sample)))
  {
    // Do nothing.
  }
  uint_fast64_t hwm = _current._hwm.load();
  while ((sample > hwm) &&
	 (!_current._hwm.compare_exchange_weak(hwm, sample)))
  {
    // Do nothing.
  }

  refresh();
}

void Accumulator::refresh(bool force)
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


void Accumulator::reset()
{
  _current._timestamp_us.store(get_timestamp_us());
  _current._n.store(0);
  _current._sigma.store(0);
  _current._sigma_squared.store(0);
  _current._lwm.store(MAX_UINT_FAST64);
  _current._hwm.store(0);
  _last._n = 0;
  _last._mean = 0;
  _last._variance = 0;
  _last._lwm = 0;
  _last._hwm = 0;
}
void Accumulator::read(uint_fast64_t period_us)
{
  uint_fast64_t n = _current._n.exchange(0);
  uint_fast64_t sigma = _current._sigma.exchange(0);
  uint_fast64_t sigma_squared = _current._sigma_squared.exchange(0);
  _last._n = n * period_us / _target_period_us;
  uint_fast64_t mean = (n > 0) ? sigma / n : 0;
  _last._mean = mean;
  _last._variance = (n > 0) ? ((sigma_squared / n) - (mean * mean)) : 0;
  uint_fast64_t lwm = _current._lwm.exchange(MAX_UINT_FAST64);
  _last._lwm = (n > 0) ? lwm : 0;
  _last._hwm = _current._hwm.exchange(0);
}

void StatisticAccumulator::refreshed()
{
  std::vector<std::string> values;
  values.push_back(std::to_string(get_mean()));
  values.push_back(std::to_string(get_variance()));
  values.push_back(std::to_string(get_lwm()));
  values.push_back(std::to_string(get_hwm()));
  values.push_back(std::to_string(get_n()));
  _statistic.report_change(values);
}

#include <atomic>
#include "utils.h"
#include "log.h"
#include <vector>
#include <map>
#include <string>
#include <atomic>

#include "log.h"
#include "event_statistic_accumulator.h"
#include "limits.h"

namespace SNMP
{

EventStatisticAccumulator::EventStatisticAccumulator()
{
  reset(0);
}

void EventStatisticAccumulator::accumulate(uint32_t sample)
{
  TRC_DEBUG("Accumulate %u for %p", sample, this);
  _count++;

  _sum += sample;
  _sqsum += (sample * sample);

  uint_fast64_t lwm = _lwm.load();
  while ((sample < lwm) &&
         (!_lwm.compare_exchange_weak(lwm, sample)))
  {
  }
  uint_fast64_t hwm = _hwm.load();
  while ((sample > hwm) &&
         (!_hwm.compare_exchange_weak(hwm, sample)))
  {
  }
}

void EventStatisticAccumulator::get_stats(EventStatistics &stats)
{
  stats.count = _count;

  if (_count > 0)
  {
    uint_fast64_t sum = _sum;
    uint_fast64_t sqsum = _sqsum;

    stats.mean = sum/stats.count;
    stats.variance = ((sqsum * stats.count) - (sum * sum)) / (stats.count * stats.count);
    stats.hwm = _hwm;
    stats.lwm = _lwm;
  }
  else
  {
    stats.mean = 0;
    stats.variance = 0;
    stats.lwm = 0;
    stats.hwm = 0;
  }
}

void EventStatisticAccumulator::reset(uint64_t periodstart, EventStatisticAccumulator* previous)
{
  _count = 0;
  _sum = 0;
  _sqsum = 0;
  _lwm = ULONG_MAX;
  _hwm = 0;
}

}

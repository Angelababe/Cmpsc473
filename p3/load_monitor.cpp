#include <atomic>
#include "load_monitor.h"
#include "log.h"
#include "snmp_continuous_accumulator_table.h"
#include "snmp_scalar.h"
#include "sasevent.h"

TokenBucket::TokenBucket(int initial_size,
                         float initial_rate_s,
                         float min_rate_s,
                         float max_rate_s) :
  _tokens(initial_size),
  _max_size(initial_size),
  _rate_s(initial_rate_s),
  _min_rate_s(min_rate_s),
  _max_rate_s(max_rate_s)
{
  clock_gettime(CLOCK_MONOTONIC, &_replenish_time_us);
}

bool TokenBucket::get_token()
{
  replenish_bucket();
  bool rc = (_tokens >= 1);

  if (rc)
  {
    _tokens -= 1;
  }

  return rc;
}

void TokenBucket::update_rate(float new_rate_s)
{
  _rate_s = (new_rate_s > _min_rate_s) ? new_rate_s : _min_rate_s;
  _rate_s = ((_max_rate_s != 0) && (_rate_s > _max_rate_s)) ? _max_rate_s : _rate_s;
}

void TokenBucket::replenish_bucket()
{
  timespec new_replenish_time_us;
  clock_gettime(CLOCK_MONOTONIC, &new_replenish_time_us);

  float timediff_us = ((new_replenish_time_us.tv_nsec - _replenish_time_us.tv_nsec) /
                       1000.0) +
                      ((new_replenish_time_us.tv_sec - _replenish_time_us.tv_sec) *
                       1000000.0);

  float new_tokens = ((_rate_s * timediff_us) / 1000000.0);
  _tokens = (new_tokens > _max_size) ? _max_size : new_tokens + _tokens;
  _replenish_time_us = new_replenish_time_us;
}

LoadMonitor::LoadMonitor(uint64_t init_target_latency_us,
                         int max_bucket_size,
                         float init_token_rate_s,
                         float init_min_token_rate_s,
                         float init_max_token_rate_s,
                         SNMP::AbstractContinuousAccumulatorTable* token_rate_table,
                         SNMP::AbstractScalar* smoothed_latency_scalar,
                         SNMP::AbstractScalar* target_latency_scalar,
                         SNMP::AbstractScalar* penalties_scalar,
                         SNMP::AbstractScalar* token_rate_scalar) :
  _bucket(max_bucket_size,
          init_token_rate_s,
          init_min_token_rate_s,
          init_max_token_rate_s),
  _smoothed_latency_us(0),
  _target_latency_us(init_target_latency_us),
  _smoothed_rate_s(0),
  _accepted(0),
  _rejected(0),
  _penalties(0),
  _adjust_count(0),
  _token_rate_table(token_rate_table),
  _smoothed_latency_scalar(smoothed_latency_scalar),
  _target_latency_scalar(target_latency_scalar),
  _penalties_scalar(penalties_scalar),
  _token_rate_scalar(token_rate_scalar)
{
  std::string max_token_fill_rate = (init_max_token_rate_s == 0) ?
    "No maximum" :
    std::to_string(init_max_token_rate_s);

  TRC_STATUS("Constructing LoadMonitor");
  TRC_STATUS("   Target latency (usecs)    : %d", init_target_latency_us);
  TRC_STATUS("   Max bucket size           : %d", max_bucket_size);
  TRC_STATUS("   Initial token fill rate/s : %f", init_token_rate_s);
  TRC_STATUS("   Min token fill rate/s     : %f", init_min_token_rate_s);
  TRC_STATUS("   Max token fill rate/s     : %s", max_token_fill_rate.c_str());

  pthread_mutexattr_t attrs;
  pthread_mutexattr_init(&attrs);
  pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&_lock, &attrs);
  pthread_mutexattr_destroy(&attrs);

  timespec current_time;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &current_time);
  _last_adjustment_time_us = (current_time.tv_sec * 1000000) +
                             (current_time.tv_nsec / 1000);

  update_statistics();
}

LoadMonitor::~LoadMonitor()
{
  pthread_mutex_destroy(&_lock);
}

bool LoadMonitor::admit_request(SAS::TrailId trail, bool allow_anyway)
{
  pthread_mutex_lock(&_lock);

  if (_bucket.get_token() || allow_anyway)
  {
    _accepted += 1;

    SAS::Event accept(trail, SASEvent::LOAD_MONITOR_ACCEPTED_REQUEST, 0);
    accept.add_static_param(_bucket.rate());
    accept.add_static_param(_bucket.token_count());
    SAS::report_event(accept);

    pthread_mutex_unlock(&_lock);
    return true;
  }
  else
  {
    _rejected += 1;

    float accepted_percent = (_accepted + _rejected == 0) ?
                             100.0 :
                             100 * ((float)_accepted / (_accepted + _rejected));
    timespec current_time;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &current_time);
    uint64_t time_passed_us = ((current_time.tv_sec * 1000000) +
                               (current_time.tv_nsec / 1000)) -
                              _last_adjustment_time_us;

    SAS::Event event(trail, SASEvent::LOAD_MONITOR_REJECTED_REQUEST, 0);
    event.add_static_param(_bucket.rate());
    event.add_static_param(accepted_percent);
    event.add_static_param(time_passed_us);
    SAS::report_event(event);

    pthread_mutex_unlock(&_lock);
    return false;
  }
}

void LoadMonitor::incr_penalties()
{
  pthread_mutex_lock(&_lock);
  _penalties += 1;
  pthread_mutex_unlock(&_lock);
}

void LoadMonitor::request_complete(uint64_t latency_us,
                                   SAS::TrailId trail)
{
  pthread_mutex_lock(&_lock);
  _smoothed_latency_us = (_smoothed_latency_us * _adjust_count + latency_us) /
                         (_adjust_count + 1);

  timespec current_time;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &current_time);
  uint64_t current_time_us = (current_time.tv_sec * 1000000) +
                             (current_time.tv_nsec / 1000);

  uint64_t us_passed = current_time_us - _last_adjustment_time_us;
  float current_rate_s = (us_passed != 0) ?
                         REQUESTS_BEFORE_ADJUSTMENT * 1000000/us_passed :
                         0;
  _smoothed_rate_s = (_smoothed_rate_s * _adjust_count + current_rate_s) /
                     (_adjust_count + 1);

  _adjust_count += 1;

  if (_adjust_count >= REQUESTS_BEFORE_ADJUSTMENT)
  {
    SAS::Event recalculate(trail, SASEvent::LOAD_MONITOR_RECALCULATE_RATE, 0);
    recalculate.add_static_param(REQUESTS_BEFORE_ADJUSTMENT);
    SAS::report_event(recalculate);

    float err = ((float)(_smoothed_latency_us) - _target_latency_us) /
                 _target_latency_us;
    TRC_INFO("Rate adjustment calculation inputs: "
             "err %f, smoothed latency %lu, target latency %lu",
             err, _smoothed_latency_us, _target_latency_us);

    if (err > DECREASE_THRESHOLD || _penalties > 0)
    {
      float old_rate_s = _bucket.rate();
      _bucket.update_rate(_bucket.rate() / DECREASE_FACTOR);

      if (_penalties > 0)
      {
        SAS::Event decrease(trail, SASEvent::LOAD_MONITOR_DECREASE_PENALTIES, 0);
        decrease.add_static_param(_bucket.rate());
        decrease.add_static_param(old_rate_s);
        SAS::report_event(decrease);
      }
      else
      {
        SAS::Event decrease(trail, SASEvent::LOAD_MONITOR_DECREASE_RATE, 0);
        decrease.add_static_param(_bucket.rate());
        decrease.add_static_param(old_rate_s);
        decrease.add_static_param(_smoothed_latency_us);
        decrease.add_static_param(_target_latency_us);
        SAS::report_event(decrease);
      }

      TRC_INFO("Maximum incoming request rate/second decreased to %f from %f "
               "(based on a smoothed mean latency of %dus, a target latency of "
               "%dus and %d overload responses).",
               _bucket.rate(),
               old_rate_s,
               _smoothed_latency_us,
               _target_latency_us,
               _penalties);
    }
    else if (err < INCREASE_THRESHOLD)
    {
      float threshold_rate_s = _bucket.rate() * PERCENTAGE_BEFORE_ADJUSTMENT;

      if (_smoothed_rate_s > threshold_rate_s)
      {
        float old_rate_s = _bucket.rate();
        float new_rate_s = _bucket.rate() +
                           (-1 * err * _bucket.max_size() * INCREASE_FACTOR);
        _bucket.update_rate(new_rate_s);

        SAS::Event increase(trail, SASEvent::LOAD_MONITOR_INCREASE_RATE, 0);
        increase.add_static_param(_bucket.rate());
        increase.add_static_param(old_rate_s);
        increase.add_static_param(_smoothed_latency_us);
        increase.add_static_param(_target_latency_us);
        SAS::report_event(increase);

        TRC_INFO("Maximum incoming request rate/second increased to %f from %f "
                 "(based on a smoothed mean latency of %dus and a target "
                 "latency of %dus).",
                 _bucket.rate(),
                 old_rate_s,
                 _smoothed_latency_us,
                 _target_latency_us);
      }
      else
      {
        SAS::Event unchanged_threshold(trail,
                                       SASEvent::LOAD_MONITOR_UNCHANGED_THRESHOLD,
                                       0);
        unchanged_threshold.add_static_param(_bucket.rate());
        unchanged_threshold.add_static_param(_smoothed_latency_us);
        unchanged_threshold.add_static_param(_target_latency_us);
        unchanged_threshold.add_static_param(_smoothed_rate_s);
        unchanged_threshold.add_static_param(threshold_rate_s);
        SAS::report_event(unchanged_threshold);

        TRC_INFO("Maximum incoming request rate/second unchanged at %f (current "
                  "request rate is %f requests/sec, minimum threshold for a "
                  "change is %f requests/sec).",
                  _bucket.rate(),
                  _smoothed_rate_s,
                  threshold_rate_s);
      }
    }
    else
    {
      SAS::Event unchanged(trail, SASEvent::LOAD_MONITOR_UNCHANGED_RATE, 0);
      unchanged.add_static_param(_bucket.rate());
      SAS::report_event(unchanged);

      TRC_DEBUG("Maximum incoming request rate/second is unchanged at %f.",
                _bucket.rate());
    }

    update_statistics();

    _last_adjustment_time_us = current_time_us;
    _adjust_count = 0;
    _accepted = 0;
    _rejected = 0;
    _penalties = 0;
    _smoothed_latency_us = 0;
    _smoothed_rate_s = 0;
  }
  else
  {
    SAS::Event unchanged(trail, SASEvent::LOAD_MONITOR_UNADJUSTED, 0);
    unchanged.add_static_param(_adjust_count);
    unchanged.add_static_param(REQUESTS_BEFORE_ADJUSTMENT);
    unchanged.add_static_param(_bucket.rate());
    unchanged.add_static_param(_smoothed_rate_s);
    unchanged.add_static_param(_smoothed_latency_us);
    unchanged.add_static_param(latency_us);
    unchanged.add_static_param(_target_latency_us);
    SAS::report_event(unchanged);

    TRC_DEBUG("Not recalculating rate as we haven't processed %d requests yet "
              "(only %d).",
              REQUESTS_BEFORE_ADJUSTMENT,
              _adjust_count);
  }

  pthread_mutex_unlock(&_lock);
}

void LoadMonitor::update_statistics()
{
  if (_smoothed_latency_scalar != NULL)
  {
    _smoothed_latency_scalar->set_value(_smoothed_latency_us);
  }

  if (_target_latency_scalar != NULL)
  {
    _target_latency_scalar->set_value(_target_latency_us);
  }

  if (_penalties_scalar != NULL)
  {
    _penalties_scalar->set_value(_penalties);
  }

  if (_token_rate_table != NULL)
  {
    _token_rate_table->accumulate(_bucket.rate());
  }

  if (_token_rate_scalar != NULL)
  {
    _token_rate_scalar->set_value(_bucket.rate());
  }
}

#include <atomic>
#include "utils.h"
#include "log.h"
#include <cassert>
#include "time.h"

#include "health_checker.h"
#include "log.h"

HealthChecker::HealthChecker() :
  _recent_passes(0),
  _hit_exception(false),
  _terminate(false)
{
  _condvar = PTHREAD_COND_INITIALIZER;
  _condvar_lock = PTHREAD_MUTEX_INITIALIZER; 

  pthread_condattr_t cond_attr;
  pthread_condattr_init(&cond_attr);
  pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
  pthread_cond_init(&_condvar, &cond_attr);
  pthread_condattr_destroy(&cond_attr);
}

HealthChecker::~HealthChecker()
{
  pthread_cond_destroy(&_condvar);
  pthread_mutex_destroy(&_condvar_lock);
}

void HealthChecker::hit_exception()
{
  _hit_exception = true;
}

void HealthChecker::health_check_passed()
{
  _recent_passes++;
}

void HealthChecker::do_check()
{
  int num_recent_passes = _recent_passes.exchange(0);
  if (_hit_exception.load() && (num_recent_passes == 0))
  {
    exit(1);
  }
  else
  {
  }
}

void* HealthChecker::static_main_thread_function(void* health_checker)
{
    ((HealthChecker*)health_checker)->main_thread_function();
    return NULL;
}

void HealthChecker::main_thread_function()
{
  struct timespec end_wait;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  end_wait.tv_sec = now.tv_sec + 60;
  end_wait.tv_nsec = now.tv_nsec;
  pthread_mutex_lock(&_condvar_lock);
  while (true)
  {
    pthread_cond_timedwait(&_condvar, &_condvar_lock, &end_wait);

    if (_terminate)
    {
      break;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &now);
    if ((now.tv_sec > end_wait.tv_sec) || ((now.tv_sec == end_wait.tv_sec) && (now.tv_nsec >= end_wait.tv_nsec)))
    {
      do_check();
      end_wait.tv_sec += 60;
    }
  }
  pthread_mutex_unlock(&_condvar_lock);
}

void HealthChecker::start_thread()
{
  pthread_create(&_health_check_thread,
                 NULL,
                 &HealthChecker::static_main_thread_function,
                 (void*)this);
 
}
void HealthChecker::stop_thread()
{
  pthread_mutex_lock(&_condvar_lock);
  _terminate = true;
  pthread_cond_signal(&_condvar);
  pthread_mutex_unlock(&_condvar_lock);
  pthread_join(_health_check_thread, NULL);
}

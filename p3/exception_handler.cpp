#include <atomic>
#include "utils.h"
#include "log.h"
#include <pthread.h>
#include <setjmp.h>
#include <unistd.h>
#include <cstdlib>
#include <signal.h>
#include <string.h>

#include "exception_handler.h"
#include "health_checker.h"
#include "log.h"

pthread_key_t _jmp_buf;

ExceptionHandler::ExceptionHandler(int ttl,
                                   bool attempt_quiesce,
                                   HealthChecker* health_checker) :
  _ttl(ttl),
  _attempt_quiesce(attempt_quiesce),
  _health_checker(health_checker),
  _dumped_core(false)
{
  pthread_key_create(&_jmp_buf, NULL);
}

ExceptionHandler::~ExceptionHandler()
{
  pthread_key_delete(_jmp_buf);
}

void ExceptionHandler::handle_exception()
{
  jmp_buf* env = (jmp_buf*)pthread_getspecific(_jmp_buf);

  if (env != NULL)
  {
    dump_one_core();

    _health_checker->hit_exception();

    longjmp(*env, 1);
  }
}

void ExceptionHandler::delayed_exit_thread()
{
  pthread_create(&_delayed_exit_thread,
                 NULL,
                 delayed_exit_thread_func,
                 (void*)this);
  pthread_detach(_delayed_exit_thread);
}

void* ExceptionHandler::delayed_exit_thread_func(void* det)
{
  int sleep_time = rand() % ((ExceptionHandler*)det)->_ttl;
  TRC_WARNING("Delayed exit will shutdown this process in %d seconds", sleep_time);
  sleep(sleep_time);

  if (((ExceptionHandler*)det)->_attempt_quiesce)
  {
    TRC_WARNING("Delayed exit attempting to quiesce process");
    raise(SIGQUIT);
    sleep(10);
  }

  TRC_WARNING("Delayed exit shutting down process");
  exit(1);
}

void ExceptionHandler::dump_one_core()
{
  bool dumped_core = _dumped_core.load();

  if (!dumped_core && _dumped_core.compare_exchange_strong(dumped_core, true))
  {
    int rc = fork();

    if (rc < 0)
    {
      char buf[256];
      fprintf(stderr, "Unable to fork to produce a core file. Error: %d %s\n",
              errno, strerror_r(errno, buf, sizeof(buf)));
    }
    else if (rc == 0)
    {
      signal(SIGABRT, SIG_DFL);

      TRC_BACKTRACE_ADV();

      TRC_COMMIT();

      abort();
    }
  }
  else
  {
    fprintf(stderr, "Not dumping core file - core has already been dumped for this process\n");
  }
}

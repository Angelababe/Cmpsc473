#include <atomic>
#include "utils.h"
#include "log.h"
#include "communicationmonitor.h"
#include "log.h"
#include "cpp_common_pd_definitions.h"

CommunicationMonitor::CommunicationMonitor(Alarm* alarm,
                                           std::string sender,
                                           std::string receiver,
                                           unsigned int clear_confirm_sec,
                                           unsigned int set_confirm_sec) :
  BaseCommunicationMonitor(),
  _alarm(alarm),
  _sender(sender),
  _receiver(receiver),
  _clear_confirm_ms(clear_confirm_sec * 1000),
  _set_confirm_ms(set_confirm_sec * 1000),
  _previous_state(0)
{
  _next_check = current_time_ms() + _set_confirm_ms;
}

CommunicationMonitor::~CommunicationMonitor()
{
  delete _alarm;
}

void CommunicationMonitor::track_communication_changes(unsigned long now_ms)
{
  now_ms = now_ms ? now_ms : current_time_ms();

  if (now_ms > _next_check)
  {
    pthread_mutex_lock(&_lock);

    if (now_ms > _next_check)
    {
      unsigned int succeeded = _succeeded.fetch_and(0);
      unsigned int failed = _failed.fetch_and(0);
      TRC_DEBUG("Checking communication changes - successful attempts %d, failures %d",
                succeeded, failed);

      int _new_state = 0;
      if ((succeeded != 0) && (failed == 0))
      {
        _new_state = NO_ERRORS;
      }
      else if ((succeeded != 0) && (failed != 0))
      {
        _new_state = SOME_ERRORS;
      }
      else if ((succeeded == 0) && (failed != 0))
      {
        _new_state = ONLY_ERRORS;
      }
      switch (_previous_state)
      {
        case NO_ERRORS:
          switch (_new_state)
          {
            case NO_ERRORS: // No change in state. Ensure alarm is cleared.
              _alarm->clear();
              break;

            case SOME_ERRORS:
              CL_CM_CONNECTION_PARTIAL_ERROR.log(_sender.c_str(),
                                                 _receiver.c_str());
              _alarm->clear();
              break;

            case ONLY_ERRORS:
              CL_CM_CONNECTION_ERRORED.log(_sender.c_str(),
                                           _receiver.c_str());
              _alarm->set();
              break;
          }
          break;
        case SOME_ERRORS:
          switch (_new_state)
          {
            case NO_ERRORS:
              CL_CM_CONNECTION_CLEARED.log(_sender.c_str(),
                                           _receiver.c_str());
              _alarm->clear();
              break;

            case SOME_ERRORS: // No change in state. Ensure alarm is cleared.
              _alarm->clear();
              break;

            case ONLY_ERRORS:
              CL_CM_CONNECTION_ERRORED.log(_sender.c_str(),
                                           _receiver.c_str());
              _alarm->set();
              break;
          }
          break;
        case ONLY_ERRORS:
          switch (_new_state)
          {
            case NO_ERRORS:
              CL_CM_CONNECTION_CLEARED.log(_sender.c_str(),
                                           _receiver.c_str());
              _alarm->clear();
              break;

            case SOME_ERRORS:
              CL_CM_CONNECTION_PARTIAL_ERROR.log(_sender.c_str(),
                                                 _receiver.c_str());
              _alarm->clear();
              break;

            case ONLY_ERRORS: // No change in state. Ensure alarm is raised.
              _alarm->set();
              break;
          }
          break;
      }
      _previous_state = _new_state;
      _next_check = (_new_state == ONLY_ERRORS) ? now_ms + _clear_confirm_ms :
                                                  now_ms + _set_confirm_ms;
    }

    pthread_mutex_unlock(&_lock);
  }
}

unsigned long CommunicationMonitor::current_time_ms()
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);

  return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

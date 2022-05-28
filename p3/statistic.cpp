#include <atomic>
#include "statistic.h"
#include "zmq_lvc.h"
#include "log.h"

#include <string>

Statistic::Statistic(std::string statname, LastValueCache* lvc) :
  _statname(statname),
  _publisher(NULL),
  _stat_q(MAX_Q_DEPTH)
{
  TRC_DEBUG("Creating %s statistic reporter", _statname.c_str());

  if (lvc != NULL)
  {
    _publisher = lvc->get_internal_publisher(statname);
  }

  int rc = pthread_create(&_reporter, NULL, &reporter_thread, (void*)this);

  if (rc < 0)
  {
    TRC_ERROR("Error creating statistic thread for %s", _statname.c_str());
 
  }
}


Statistic::~Statistic()
{
  _stat_q.terminate();

  pthread_join(_reporter, NULL);
}

void Statistic::report_change(std::vector<std::string> new_value)
{
  if (!_stat_q.push_noblock(new_value))
  {
    TRC_DEBUG("Statistic %s queue overflowed", _statname.c_str());
  }
}


void Statistic::reporter()
{
  TRC_DEBUG("Initializing inproc://%s statistic reporter", _statname.c_str());

  std::vector<std::string> new_value;

  while (_stat_q.pop(new_value))
  {
    if (_publisher != NULL)
    {
      TRC_DEBUG("Send new value for statistic %s, size %d",
                _statname.c_str(),
                new_value.size());
      std::string status = "OK";

      if (new_value.empty())
      {
        zmq_send(_publisher, _statname.c_str(), _statname.length(), ZMQ_SNDMORE);
        zmq_send(_publisher, status.c_str(), status.length(), 0);
      }
      else
      {
        zmq_send(_publisher, _statname.c_str(), _statname.length(), ZMQ_SNDMORE);
        zmq_send(_publisher, status.c_str(), status.length(), ZMQ_SNDMORE);
        std::vector<std::string>::iterator it;
        for (it = new_value.begin(); it + 1 != new_value.end(); ++it)
        {
          zmq_send(_publisher, it->c_str(), it->length(), ZMQ_SNDMORE); 
        }
        zmq_send(_publisher, it->c_str(), it->length(), 0);
      }
    }
  }
}


void* Statistic::reporter_thread(void* p)
{
  ((Statistic*)p)->reporter();
  return NULL;
}



#include <atomic>
#include "utils.h"
#include "log.h"
#include "base_communication_monitor.h"

BaseCommunicationMonitor::BaseCommunicationMonitor() :
  _succeeded(0),
  _failed(0)
{
  pthread_mutex_init(&_lock, NULL);
}

BaseCommunicationMonitor::~BaseCommunicationMonitor()
{
  pthread_mutex_destroy(&_lock);
}

void BaseCommunicationMonitor::inform_success(unsigned long now_ms)
{
  _succeeded++;
  track_communication_changes(now_ms);
}

void BaseCommunicationMonitor::inform_failure(unsigned long now_ms)
{
  _failed++;
  track_communication_changes(now_ms);
}

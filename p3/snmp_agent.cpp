#include <atomic>
#include <limits.h>
#include <net-snmp/library/large_fd_set.h>
#include "snmp_internal/snmp_includes.h"
#include "snmp_agent.h"
#include "log.h"

namespace SNMP
{

Agent* Agent::_instance = NULL;

void Agent::instantiate(std::string name)
{
  delete(_instance);
  _instance = NULL;
  _instance = new Agent(name);
}

void Agent::deinstantiate()
{
  delete(_instance);
  _instance = NULL;
}

Agent::Agent(std::string name) : _name(name)
{
  pthread_mutex_lock(&_netsnmp_lock);

  netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

  std::string persistent_file = "/tmp/";
  persistent_file.append(_name.c_str());
  netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                        NETSNMP_DS_LIB_PERSISTENT_DIR,
                        persistent_file.c_str());

  snmp_enable_calllog();
  snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, logging_callback, NULL);

  netsnmp_container_init_list();
  int rc = init_agent(_name.c_str());
  if (rc != 0)
  {
    snmp_unregister_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, logging_callback, NULL, 1);
    netsnmp_container_free_list();
  }

  pthread_mutex_unlock(&_netsnmp_lock);

  if (rc != 0)
  {
    throw rc;
  }
}

Agent::~Agent()
{
  snmp_unregister_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, logging_callback, NULL, 1);
  netsnmp_container_free_list();
}

void Agent::start(void)
{
  pthread_mutex_lock(&_netsnmp_lock);
  init_snmp(_name.c_str());
  pthread_mutex_unlock(&_netsnmp_lock);

  int rc = pthread_create(&_thread, NULL, thread_fn, this);
  if (rc != 0)
  {
    throw rc;
  }
}

void Agent::stop(void)
{
  pthread_cancel(_thread);
  pthread_join(_thread, NULL);

  pthread_mutex_lock(&_netsnmp_lock);
  snmp_shutdown(_name.c_str());
  netsnmp_container_free_list();
  pthread_mutex_unlock(&_netsnmp_lock);
}

void Agent::add_row_to_table(netsnmp_tdata* table, netsnmp_tdata_row* row)
{
  pthread_mutex_lock(&_netsnmp_lock);
  netsnmp_tdata_add_row(table, row);
  pthread_mutex_unlock(&_netsnmp_lock);
}

void Agent::remove_row_from_table(netsnmp_tdata* table, netsnmp_tdata_row* row)
{
  pthread_mutex_lock(&_netsnmp_lock);
  netsnmp_tdata_remove_row(table, row);
  pthread_mutex_unlock(&_netsnmp_lock);
}

void* Agent::thread_fn(void* snmp_agent)
{
  ((Agent*)snmp_agent)->thread_fn();
  return NULL;
}

void Agent::thread_fn()
{
  int num_fds;
  netsnmp_large_fd_set read_fds;
  netsnmp_large_fd_set_init(&read_fds, FD_SETSIZE);
  struct timeval timeout;
  int block;

  while (1)
  {
    num_fds = 0;
    NETSNMP_LARGE_FD_ZERO(&read_fds);
    timeout.tv_sec = LONG_MAX;
    timeout.tv_usec = 0;
    block = 0;
    pthread_mutex_lock(&_netsnmp_lock);
    snmp_select_info2(&num_fds, &read_fds, &timeout, &block);
    pthread_mutex_unlock(&_netsnmp_lock);

    int select_rc = netsnmp_large_fd_set_select(num_fds, &read_fds, NULL, NULL, (!block) ? &timeout : NULL);

    if (select_rc >= 0)
    {
      pthread_mutex_lock(&_netsnmp_lock);
      if (select_rc > 0)
      {
        snmp_read2(&read_fds);
      }
      else if (select_rc == 0)
      {
        snmp_timeout();
      }

      run_alarms();

      netsnmp_check_outstanding_agent_requests();

      pthread_mutex_unlock(&_netsnmp_lock);
    }
    else if ((select_rc != -1) || (errno != EINTR))
    {.
      TRC_WARNING("SNMP select failed with RC %d (errno: %d)", select_rc, errno);
    }
  }
};

int Agent::logging_callback(int majorID, int minorID, void* serverarg, void* clientarg)
{
  snmp_log_message* log_message = (snmp_log_message*)serverarg;
  int snmp_priority = log_message->priority;
  int clearwater_priority = Log::STATUS_LEVEL;

  switch (snmp_priority) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
      clearwater_priority = Log::ERROR_LEVEL;
      break;
    case LOG_WARNING:
      clearwater_priority = Log::WARNING_LEVEL;
      break;
    case LOG_NOTICE:
      clearwater_priority = Log::STATUS_LEVEL;
      break;
    case LOG_INFO:
      clearwater_priority = Log::INFO_LEVEL;
      break;
    case LOG_DEBUG:
      clearwater_priority = Log::DEBUG_LEVEL;
      break;
  }

  if (clearwater_priority <= Log::loggingLevel)
  {
    char* orig_msg = strdup(log_message->msg);
    char* msg = orig_msg;
    msg[strlen(msg) - 1] = '\0';
    Log::write(clearwater_priority, "(Net-SNMP)", 0, msg);
    free(orig_msg);
  }

  return 0;
}

}

int snmp_setup(const char* name)
{
  // if so.
  if (SNMP::Agent::instance() != NULL)
  {
    SNMP::Agent::deinstantiate();
  }

  try
  {
    SNMP::Agent::instantiate(name);
    TRC_STATUS("AgentX agent initialised");
    return 0;
  }
  catch (int rc)
  {
    TRC_WARNING("SNMP AgentX initialization failed");
    return rc;
  }
}
int init_snmp_handler_threads(const char* name)
{
  try
  {
    SNMP::Agent::instance()->start();
    return 0;
  }
  catch (int rc)
  {
    return rc;
  }
}
void snmp_terminate(const char* name)
{
  SNMP::Agent::instance()->stop();

}

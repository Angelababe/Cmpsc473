#include <atomic>
#include <cstdarg>

#include "log.h"
#include "saslogger.h"


void sas_write(SAS::sas_log_level_t sas_level,
               int32_t log_id_len,
               unsigned char* log_id,
               int32_t sas_ip_len,
               unsigned char* sas_ip,
               int32_t msg_len,
               unsigned char* msg)
{
  int level;

  switch (sas_level) {
    case SAS::SASCLIENT_LOG_CRITICAL:
      level = Log::ERROR_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_ERROR:
      level = Log::ERROR_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_WARNING:
      level = Log::WARNING_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_INFO:
      level = Log::STATUS_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_DEBUG:
      level = Log::DEBUG_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_TRACE:
      level = Log::DEBUG_LEVEL;
      break;
    case SAS::SASCLIENT_LOG_STATS:
      level = Log::INFO_LEVEL;
      break;
    default:
      TRC_ERROR("Unknown SAS log level %d, treating as error level", sas_level);
      level = Log::ERROR_LEVEL;
    }

  Log::write(level,
             NULL,
             0,
             "%.*s %.*s %.*s",
             log_id_len, log_id, sas_ip_len, sas_ip, msg_len, msg);
}

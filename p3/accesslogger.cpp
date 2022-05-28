#include <atomic>
#include "utils.h"
#include "log.h"
#include <stdio.h>

#include "accesslogger.h"

AccessLogger::AccessLogger(const std::string& directory)
{
  _logger = new Logger(directory, std::string("access"));
  _logger->set_flags(Logger::ADD_TIMESTAMPS|Logger::FLUSH_ON_WRITE);
}

AccessLogger::~AccessLogger()
{
  delete _logger;
}

void AccessLogger::log(const std::string& uri,
                       const std::string& method,
                       int rc,
                       unsigned long latency_us)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "%d %s %s %ld.%6.6ld seconds\n",
           rc,
           method.c_str(),
           uri.c_str(),
           latency_us / 1000000,
           latency_us % 1000000);
  _logger->write(buf);
}

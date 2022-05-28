#include <atomic>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <algorithm>
#include <time.h>
#include "log.h"

const char* log_level[] = {"Error", "Warning", "Status", "Info", "Verbose", "Debug"};

#define MAX_LOGLINE 8192

namespace Log
{
  static Logger logger_static;
  static Logger *logger = &logger_static;
  static pthread_mutex_t serialization_lock = PTHREAD_MUTEX_INITIALIZER;
  int loggingLevel = 4;
}

void Log::setLoggingLevel(int level)
{
  if (level > DEBUG_LEVEL)
  {
    level = DEBUG_LEVEL;
  }
  else if (level < ERROR_LEVEL)
  {
    level = ERROR_LEVEL;
  }
  Log::loggingLevel = level;
}
Logger* Log::setLogger(Logger *log)
{
  pthread_mutex_lock(&Log::serialization_lock);
  Logger* old = Log::logger;
  Log::logger = log;
  if (Log::logger != NULL)
  {
    Log::logger->set_flags(Logger::FLUSH_ON_WRITE|Logger::ADD_TIMESTAMPS);
  }
  pthread_mutex_unlock(&Log::serialization_lock);
  return old;
}

void Log::write(int level, const char *module, int line_number, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  _write(level, module, line_number, fmt, args);
  va_end(args);
}

static void release_lock(void* notused) { pthread_mutex_unlock(&Log::serialization_lock); } // LCOV_EXCL_LINE

static void log_helper(char* logline,
                int& written,
                int& truncated,
                int level,
                const char *module,
                int line_number,
                const char* context,
                const char *fmt,
                va_list args)
{
  written = 0;
  truncated = 0;

  pthread_t thread = pthread_self();

  written = snprintf(logline, MAX_LOGLINE -2, "[%lx] %s ", thread, log_level[level]);
  int bytes_available = MAX_LOGLINE - wr
  if (module != NULL)
  {
    const char* mod = strrchr(module, '/');
    module = (mod != NULL) ? mod + 1 : module;

    if (line_number)
    {
      if (context)
      {
        written += snprintf(logline + written, bytes_available, "%s:%d:%s: ", module, line_number, context);
      }
      else
      {
        written += snprintf(logline + written, bytes_available, "%s:%d: ", module, line_number);
      }
    }
    else
    {
      if (context)
      {
        written += snprintf(logline + written, bytes_available, "%s:%s: ", module, context);
      }
      else
      {
        written += snprintf(logline + written, bytes_available, "%s: ", module);
      }
    }
  }

  written = std::min(written, MAX_LOGLINE - 1);

  bytes_available = MAX_LOGLINE - written - 1;
  written += vsnprintf(logline + written, bytes_available, fmt, args);

  if (written > (MAX_LOGLINE - 1))
  {
    truncated = written - (MAX_LOGLINE - 2);
    written = MAX_LOGLINE - 2;
  }
  logline[written] = '\n';
  written++;
}


void Log::_write(int level, const char *module, int line_number, const char *fmt, va_list args)
{
  if (level > Log::loggingLevel)
  {
    return;
  }

  pthread_mutex_lock(&Log::serialization_lock);
  if (!Log::logger)
  {
    pthread_mutex_unlock(&Log::serialization_lock);
    return;
  }

  pthread_cleanup_push(release_lock, 0);

  char logline[MAX_LOGLINE];
  int written;
  int truncated;

  log_helper(logline, written, truncated, level, module, line_number, nullptr, fmt, args);

  logline[written] = '\0';

  Log::logger->write(logline);
  if (truncated > 0)
  {
    char buf[128];
    snprintf(buf, 128, "Previous log was truncated by %d characters\n", truncated);
    Log::logger->write(buf);
  }

  pthread_cleanup_pop(0);
  pthread_mutex_unlock(&Log::serialization_lock);
}


void Log::backtrace(const char *fmt, ...)
{
  if (!Log::logger)
  {
    return;
  }

  va_list args;
  char logline[MAX_LOGLINE];
  va_start(args, fmt);
  int written = vsnprintf(logline, MAX_LOGLINE - 2, fmt, args);
  written = std::min(written, MAX_LOGLINE - 2);
  va_end(args);

  logline[written] = '\n';
  logline[written+1] = '\0';

  Log::logger->backtrace_simple(logline);
}

void Log::backtrace_adv()
{
  if (!Log::logger)
  {
    return;
  }

  Log::logger->backtrace_advanced();
}

void Log::commit()
{
  if (!Log::logger)
  {
    return;
  }

  Log::logger->commit();
}

#define RAM_BUFFER_SIZE 20971520

namespace RamRecorder
{
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  static char buffer[RAM_BUFFER_SIZE];

  static char* window_start = buffer;
  static char* window_end = buffer;
  bool record_everything = false;
}

void RamRecorder::recordEverything()
{
  RamRecorder::record_everything = true;
}

void RamRecorder::_record(int level, const char* module, int lineno, const char* context, const char* format, va_list args)
{
  int truncated;

  {
    char logline[MAX_LOGLINE + 100];

    int timestamp_length;

    {
      timestamp_t ts;
      struct timespec timespec;
      clock_gettime(CLOCK_REALTIME, &timespec);
      Logger::get_timestamp(ts, timespec);
      Logger::format_timestamp(ts, logline, 100);
      timestamp_length = strlen(logline);

      logline[timestamp_length] = ' ';
      timestamp_length += 1;
    }

    int logline_length;

    log_helper(logline + timestamp_length, logline_length, truncated, level, module, lineno, context, format, args);

    RamRecorder::write(logline, logline_length + timestamp_length);
  }

  if (truncated)
  {
    char buf[128];
    int len = snprintf(buf, 128, "Earlier log was truncated by %d characters\n", truncated);
    RamRecorder::write(buf, len);
  }
}

void RamRecorder::record(int level, const char* module, int lineno, const char* format, ...)
{
  va_list args;
  va_start(args, format);
  _record(level, module, lineno, nullptr, format, args);
  va_end(args);
}

void RamRecorder::record_with_context(int level, const char* module, int lineno, const char* context, const char* format, ...)
{
  va_list args;
  va_start(args, format);
  _record(level, module, lineno, context, format, args);
  va_end(args);
}

void RamRecorder::reset()
{
  RamRecorder::record_everything = false;
  pthread_mutex_lock(&RamRecorder::lock);
  window_end = buffer;
  window_start = buffer;
  pthread_mutex_unlock(&RamRecorder::lock);
}

void RamRecorder::write(const char* message, size_t length)
{
  pthread_mutex_lock(&RamRecorder::lock);
  const char* buffer_end = buffer + RAM_BUFFER_SIZE;

  while (length > 0)
  {
    size_t bytes_left_in_buffer = buffer_end - window_end;

    size_t bytes_to_write = std::min(length, bytes_left_in_buffer);

    memcpy(window_end, message, bytes_to_write);

    length -= bytes_to_write;

    message += bytes_to_write;

    if (bytes_to_write == bytes_left_in_buffer)
    {

      char* new_window_end = buffer;

      if ((window_end < window_start) ||
          (window_start == new_window_end))
      {
        window_start = buffer + 1;
      }

      window_end = new_window_end;
    }
    else
    {
      char* new_window_end = window_end + bytes_to_write;

      if (window_end < window_start)
      {

        if (new_window_end >= window_start)
        {
          window_start = new_window_end + 1;

          if (window_start >= buffer_end)
          {
            window_start = buffer;
          }
        }
      }

      window_end = new_window_end;
    }
  }

  pthread_mutex_unlock(&RamRecorder::lock);
}

void RamRecorder::dump(const std::string& output_dir)
{
  std::string file_name = output_dir + "/ramtrace." + std::to_string(time(NULL)) + ".txt";

  FILE *file = fopen(file_name.c_str(), "w");

  if (file)
  {
    fprintf(file, "RAM BUFFER\n==========\n");

    pthread_mutex_lock(&RamRecorder::lock);

    if (window_end == window_start)
    {
      fprintf(file, "No recorded logs\n");
    }
    else if (window_end > window_start)
    {
      fwrite(window_start,
             sizeof(char),
             window_end - window_start,
             file);
    }
    else
    {
      const char* end = buffer + RAM_BUFFER_SIZE;
      fwrite(window_start,
             sizeof(char),
             end - window_start,
             file);
      fwrite(buffer,
             sizeof(char),
             window_end - buffer,
             file);
    }

    pthread_mutex_unlock(&RamRecorder::lock);

    fprintf(file, "==========\n");

    fclose(file);
  }
  else
  {
    TRC_ERROR("Failed to open file to dump RAM buffer!\n");
  }
}

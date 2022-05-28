#include <atomic>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <execinfo.h>
#include <string.h>

#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "logger.h"

const double Logger::LOGFILE_RETRY_FREQUENCY = 5.0;

Logger::Logger() :
  _flags(ADD_TIMESTAMPS),
  _last_hour(0),
  _rotate(false),
  _last_rotate({0}),
  _fd(stdout)
{
  pthread_mutex_init(&_lock, NULL);
}


Logger::Logger(const std::string& directory, const std::string& filename) :
  _flags(ADD_TIMESTAMPS),
  _last_hour(0),
  _rotate(true),
  _last_rotate({0}),
  _fd(NULL),
  _discards(0),
  _saved_errno(0),
  _filename(filename),
  _directory(directory)
{
  pthread_mutex_init(&_lock, NULL);
}


Logger::~Logger()
{
}


int Logger::get_flags() const
{
  return _flags;
}


void Logger::set_flags(int flags)
{
  _flags = flags;
}


void Logger::gettime(struct timespec* ts)
{
  clock_gettime(CLOCK_REALTIME, ts);
}


void Logger::gettime_monotonic(struct timespec* ts)
{
  clock_gettime(CLOCK_MONOTONIC, ts);
}

void Logger::write(const char* data)
{
  timestamp_t ts;
  get_timestamp(ts);

  pthread_mutex_lock(&_lock);
  pthread_cleanup_push(Logger::release_lock, this);

  bool cycle_log_file_required = false;

  if (_fd == NULL)
  {
    struct timespec current_time;
    gettime_monotonic(&current_time);
    double seconds = difftime(current_time.tv_sec, _last_rotate.tv_
    if ((seconds > LOGFILE_RETRY_FREQUENCY) ||
        (current_time.tv_sec < LOGFILE_RETRY_FREQUENCY))
     {
      cycle_log_file_required = true;
    }
  }
  else
  {
    int hour = ts.year * 366 * 24 + ts.yday * 24 + ts.hour;
    if (_rotate && (hour > _last_hour))
    {
      cycle_log_file_required = true;
      _last_hour = hour;
    }
  }

  if (cycle_log_file_required)
  {
    cycle_log_file(ts);
    gettime_monotonic(&_last_rotate);

    if ((_fd != NULL) &&
        (_discards != 0))
    {
      char discard_msg[100];
      sprintf(discard_msg,
              "Failed to open logfile (%d - %s), %d logs discarded\n",
              _saved_errno, ::strerror(_saved_errno), _discards);
      write_log_file(discard_msg, ts);
      _discards = 0;
      _saved_errno = 0;
    }
  }

  if (_fd != NULL)
  {
    write_log_file(data, ts);
  }
  else
  {
    ++_discards;
  }

  pthread_cleanup_pop(0);
  pthread_mutex_unlock(&_lock);
}

void Logger::get_timestamp(timestamp_t& ts)
{
  struct timespec timespec;
  gettime(&timespec);
  get_timestamp(ts, timespec);
}

void Logger::get_timestamp(timestamp_t& ts, struct timespec& timespec)
{
  struct tm dt;
  gmtime_r(&timespec.tv_sec, &dt);
  ts.year = dt.tm_year;
  ts.mon = dt.tm_mon;
  ts.mday = dt.tm_mday;
  ts.hour = dt.tm_hour;
  ts.min = dt.tm_min;
  ts.sec = dt.tm_sec;
  ts.msec = (int)(timespec.tv_nsec / 1000000);
  ts.yday = dt.tm_yday;
}

void Logger::format_timestamp(const timestamp_t& ts, char* buf, size_t len)
{
  snprintf(buf, len,
           "%2.2d-%2.2d-%4.4d %2.2d:%2.2d:%2.2d.%3.3d UTC",
           ts.mday, (ts.mon+1), (ts.year + 1900),
           ts.hour, ts.min, ts.sec, ts.msec);
}

void Logger::write_log_file(const char *data, const timestamp_t& ts)
{
  if (_flags & ADD_TIMESTAMPS)
  {
    char timestamp[100];
    format_timestamp(ts, timestamp, sizeof(timestamp));
    fprintf(_fd, "%s ", timestamp);
  }

  fputs(data, _fd);

  if (_flags & FLUSH_ON_WRITE)
  {
    fflush(_fd);
  }

  if (ferror(_fd))
  {
    fclose(_fd);
    _fd = NULL;
  }
}


void Logger::cycle_log_file(const timestamp_t& ts)
{
  if (_fd != NULL)
  {
    fclose(_fd);
  }

  std::string prefix = _directory + "/" + _filename + "_";
  char time_date_stamp[100];
  sprintf(time_date_stamp, "%4.4d%2.2d%2.2dT%2.2d0000Z",
          (ts.year + 1900),
          (ts.mon + 1),
          ts.mday,
          ts.hour);
  std::string full_path = prefix + time_date_stamp + ".txt";

  _fd = fopen(full_path.c_str(), "a");

  std::string symlink_path = prefix + "current.txt";
  std::string relative_path = "./" + _filename + "_" + time_date_stamp + ".txt";
  unlink(symlink_path.c_str());

  if (symlink(relative_path.c_str(), symlink_path.c_str()) < 0)
  {
  }

  if (_fd == NULL)
  {
    _saved_errno = errno;
  }
}

#define MAX_BACKTRACE_STACK_ENTRIES 32

void Logger::backtrace_simple(const char* data)
{
  if (_fd != NULL)
  {
    fprintf(_fd, "\n%s", data);
    fprintf(_fd, "\nBasic stack dump:\n");
    fflush(_fd);
    void *stack[MAX_BACKTRACE_STACK_ENTRIES];
    size_t num_entries = ::backtrace(stack, MAX_BACKTRACE_STACK_ENTRIES);
    backtrace_symbols_fd(stack, num_entries, fileno(_fd));
    fprintf(_fd, "\n");

    fflush(_fd);

    if (ferror(_fd))
    {
      fclose(_fd);
      _fd = NULL;
    }
  }
}
void Logger::backtrace_advanced()
{
  if (_fd != NULL)
  {
    int fd1 = dup(1);
    dup2(2, 1);

    timestamp_t ts;
    char timestamp[100];
    get_timestamp(ts);
    format_timestamp(ts, timestamp, sizeof(timestamp));
    fprintf(stderr, "\n%s Advanced stack dump (requires gdb):\n", timestamp); fflush(stderr);

    char gdb_cmd[256];
    sprintf(gdb_cmd,
            "/usr/bin/gdb -nx --batch /proc/%d/exe %d -ex 'thread apply all bt'",
            getpid(),
            getpid());
    int rc = system(gdb_cmd);

    if (rc != 0)
    {
      fprintf(stderr, "gdb failed with return code %d\n", rc); fflush(stderr);
    }

    dup2(fd1, 1);
    close(fd1);

    if (rc != 0)
    {
      fprintf(_fd, "\nAdvanced stack dump failed: gdb returned %d\n\n", rc);
    }
    else
    {
      fprintf(_fd, "\nAdvanced stack dump written to stderr (with timestamp %s)\n\n",
              timestamp);
    }

    fflush(_fd);

    if (ferror(_fd))
    {
      fclose(_fd);
      _fd = NULL;
    }
  }
}

void Logger::commit()
{
  fsync(fileno(_fd));
}



void Logger::flush()
{
  fflush(_fd);
}

#include <atomic>
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <arpa/inet.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/stat.h>
#include <syslog.h>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include "utils.h"
#include "log.h"

bool Utils::parse_http_url(
    const std::string& url,
    std::string& scheme,
    std::string& server,
    std::string& path)
{
  size_t colon_pos = url.find(':');
  if (colon_pos == std::string::npos)
  {
    // No colon - no good!
    return false;
  }

  scheme = url.substr(0, colon_pos);
  if ((scheme != "http") && (scheme != "https"))
  {
    // Not HTTP or HTTPS.
    return false;
  }
  size_t slash_slash_pos = url.find("//", colon_pos + 1);
  if (slash_slash_pos != colon_pos + 1)
  {
    // Not full URL.
    return false;
  }
  size_t slash_pos = url.find('/', slash_slash_pos + 2);
  if (slash_pos == std::string::npos)
  {
    // No path.
    server = url.substr(slash_slash_pos + 2);
    path = "/";
  }
  else
  {
    server = url.substr(slash_slash_pos + 2, slash_pos - (slash_slash_pos + 2));
    path = url.substr(slash_pos);
  }
  return true;
}

#define REPLACE(CHAR1, CHAR2, RESULT) if ((s[(ii+1)] == CHAR1) && (s[(ii+2)] == CHAR2)) { r.append(RESULT); ii = ii+2; continue; }

std::string Utils::url_unescape(const std::string& s)
{
  std::string r;
  r.reserve(s.length());

  for (size_t ii = 0; ii < s.length(); ++ii)
  {
    if (((ii + 2) < s.length()) && (s[ii] == '%'))
    {
      REPLACE('2', '1', "!");
      REPLACE('2', '3', "#");
      REPLACE('2', '4', "$");
      REPLACE('2', '6', "&");
      REPLACE('2', '7', "'");
      REPLACE('2', '8', "(");
      REPLACE('2', '9', ")");
      REPLACE('2', 'A', "*");
      REPLACE('2', 'B', "+");
      REPLACE('2', 'C', ",");
      REPLACE('2', 'F', "/");
      REPLACE('3', 'A', ":");
      REPLACE('3', 'B', ";");
      REPLACE('3', 'D', "=");
      REPLACE('3', 'F', "?");
      REPLACE('4', '0', "@");
      REPLACE('5', 'B', "[");
      REPLACE('5', 'D', "]");

      REPLACE('2', '0', " ");
      REPLACE('2', '2', "\"");
      REPLACE('2', '5', "%");
      REPLACE('2', 'D', "-");
      REPLACE('2', 'E', ".");
      REPLACE('3', 'C', "<");
      REPLACE('3', 'E', ">");
      REPLACE('5', 'C', "\\");
      REPLACE('5', 'E', "^");
      REPLACE('5', 'F', "_");
      REPLACE('6', '0', "`");
      REPLACE('7', 'B', "{");
      REPLACE('7', 'C', "|");
      REPLACE('7', 'D', "}");
      REPLACE('7', 'E', "~");

    }
    r.push_back(s[ii]);
  }
  return r;
}

std::string Utils::quote_string(const std::string& s)
{
  std::string r = "\"";
  r.reserve((2*s.length()) + 2); 

  for (size_t ii = 0; ii < s.length(); ++ii)
  {
    char unquot = s[ii];
    switch (unquot)
    {
      case '"':
      case '\\':
        r.push_back('\\');
        break;

      default:
        break;
    }

    r.push_back(unquot);
  }

  r.push_back('"');

  return r;
}

std::string Utils::url_escape(const std::string& s)
{
  std::string r;
  r.reserve(2*s.length());  

  for (size_t ii = 0; ii < s.length(); ++ii)
  {
    switch (s[ii])
    {
      case 0x21: r.append("%21"); break; // !
      case 0x23: r.append("%23"); break; // #
      case 0x24: r.append("%24"); break; // $
      case 0x25: r.append("%25"); break; // %
      case 0x26: r.append("%26"); break; // &
      case 0x27: r.append("%27"); break; // '
      case 0x28: r.append("%28"); break; // (
      case 0x29: r.append("%29"); break; // )
      case 0x2a: r.append("%2A"); break; // *
      case 0x2b: r.append("%2B"); break; // +
      case 0x2c: r.append("%2C"); break; // ,
      case 0x2f: r.append("%2F"); break; // forward slash
      case 0x3a: r.append("%3A"); break; // :
      case 0x3b: r.append("%3B"); break; // ;
      case 0x3d: r.append("%3D"); break; // =
      case 0x3f: r.append("%3F"); break; // ?
      case 0x40: r.append("%40"); break; // @
      case 0x5b: r.append("%5B"); break; // [
      case 0x5d: r.append("%5D"); break; // ]
      case 0x20: r.append("%20"); break; // space
      case 0x22: r.append("%22"); break; // "
      case 0x3c: r.append("%3C"); break; // <
      case 0x3e: r.append("%3E"); break; // >
      case 0x5c: r.append("%5C"); break; // backslash
      case 0x5e: r.append("%5E"); break; // ^
      case 0x60: r.append("%60"); break; // `
      case 0x7b: r.append("%7B"); break; // {
      case 0x7c: r.append("%7C"); break; // |
      case 0x7d: r.append("%7D"); break; // }
      case 0x7e: r.append("%7E"); break; // ~

      // Otherwise, append the literal character
      default: r.push_back(s[ii]); break;
    }
  }
  return r;
}


std::string Utils::xml_escape(const std::string& s)
{
  std::string r;
  r.reserve(2*s.length()); 

  for (size_t ii = 0; ii < s.length(); ++ii)
  {
    switch (s[ii])
    {
      case '&':  r.append("&amp;"); break;
      case '\"': r.append("&quot;"); break;
      case '\'': r.append("&apos;"); break;
      case '<':  r.append("&lt;"); break;
      case '>':  r.append("&gt;"); break;

      // Otherwise, append the literal character
      default: r.push_back(s[ii]); break;
    }
  }
  return r;
}

std::string Utils::strip_uri_scheme(const std::string& uri)
{
  std::string s(uri);
  size_t colon = s.find(':');

  if (colon != std::string::npos)
  {
    s.erase(0, colon + 1);
  }

  return s;
}

std::string Utils::remove_visual_separators(const std::string& number)
{
  static const boost::regex CHARS_TO_STRIP = boost::regex("[.)(-]");
  return boost::regex_replace(number, CHARS_TO_STRIP, std::string(""));
}

bool Utils::is_user_numeric(const std::string& user)
{
  return is_user_numeric(user.c_str(), user.length());
}

bool Utils::is_user_numeric(const char* user, size_t user_len)
{
  for (size_t i = 0; i < user_len; i++)
  {
    if (((user[i] >= '0') &&
         (user[i] <= '9')) ||
        (user[i] == '+') ||
        (user[i] == '-') ||
        (user[i] == '.') ||
        (user[i] == '(') ||
        (user[i] == ')') ||
        (user[i] == '[') ||
        (user[i] == ']'))
    {
      continue;
    }
    else
    {
      return false;
    }
  }

  return true;
}

std::string Utils::ip_addr_to_arpa(IP46Address ip_addr)
{
  std::string hostname;

  if (ip_addr.af == AF_INET)
  {
    char ipv4_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr.addr.ipv6, ipv4_addr, INET_ADDRSTRLEN);
    hostname = ipv4_addr;
  }
  else if (ip_addr.af == AF_INET6)
  {
    char buf[100];
    char* p = buf;
    for (int ii = 15; ii >= 0; ii--)
    {
      p += snprintf(p,
                    100 - (p - buf),
                    "%x.%x.",
                    ip_addr.addr.ipv6.s6_addr[ii] & 0xF,
                    ip_addr.addr.ipv6.s6_addr[ii] >> 4);
    }
    hostname = std::string(buf, p - buf);
    hostname += "ip6.arpa";
  }

  return hostname;
}

void Utils::create_random_token(size_t length,      
                                std::string& token) 
{
  token.reserve(length);

  for (size_t ii = 0; ii < length; ++ii)
  {
    token += _b64[rand() % 64];
  }
}

std::string Utils::hex(const uint8_t* data, size_t len)
{
  static const char* const hex_lookup = "0123456789abcdef";
  std::string result;
  result.reserve(2 * len);
  for (size_t ii = 0; ii < len; ++ii)
  {
    const uint8_t b = data[ii];
    result.push_back(hex_lookup[b >> 4]);
    result.push_back(hex_lookup[b & 0x0f]);
  }
  return result;
}
void Utils::hashToHex(unsigned char *hash_char, unsigned char *hex_char)
{
  unsigned short ii;
  unsigned char jj;
  unsigned char *hc = (unsigned char *) hash_char;

  for (ii = 0; ii < MD5_HASH_SIZE; ii++)
  {
    jj = (hc[ii] >> 4) & 0xf;

    if (jj <= 9)
    {
      hex_char[ii * 2] = (jj + '0');
    }
    else
    {
      hex_char[ii * 2] = (jj + 'a' - 10);
    }

    jj = hc[ii] & 0xf;

    if (jj <= 9)
    {
      hex_char[ii * 2 + 1] = (jj + '0');
    }
    else
    {
      hex_char[ii * 2 + 1] = (jj + 'a' - 10);
    }
  };

  hex_char[HEX_HASH_SIZE] = '\0';
}


bool Utils::StopWatch::_already_logged = false;

bool Utils::split_host_port(const std::string& host_port,
                            std::string& host,
                            int& port)
{
  std::vector<std::string> host_port_parts;
  size_t close_bracket = host_port.find(']');

  if (close_bracket == host_port.npos)
  {
    Utils::split_string(host_port, ':', host_port_parts, 0, false, false, true);
    if (host_port_parts.size() != 2)
    {
      TRC_DEBUG("Malformed host/port %s", host_port.c_str());
      return false;
    }
  }
  else
  {
    Utils::split_string(host_port, ']', host_port_parts);
    if ((host_port_parts.size() != 2) ||
        (host_port_parts[0][0] != '[') ||
        (host_port_parts[1][0] != ':'))
    {
      TRC_DEBUG("Malformed host/port %s", host_port.c_str());
      return false;
    }

    host_port_parts[0].erase(host_port_parts[0].begin());
    host_port_parts[1].erase(host_port_parts[1].begin());
  }

  port = atoi(host_port_parts[1].c_str());
  host = host_port_parts[0];
  if (std::to_string(port) != host_port_parts[1])
  {
    TRC_DEBUG("Malformed port %s", host_port_parts[1].c_str());
    return false;
  }

  return true;
}
bool Utils::parse_ip_target(const std::string& target, IP46Address& address)
{
  TRC_DEBUG("Attempt to parse %s as IP address", target.c_str());
  bool rc = false;
  std::string ip_target = Utils::remove_brackets_from_ip(target);
  Utils::trim(ip_target);

  if (inet_pton(AF_INET6, ip_target.c_str(), &address.addr.ipv6) == 1)
  {
    address.af = AF_INET6;
    rc = true;
  }
  else if (inet_pton(AF_INET, ip_target.c_str(), &address.addr.ipv4) == 1)
  {
    address.af = AF_INET;
    rc = true;
  }

  return rc;
}

bool Utils::overflow_less_than(uint32_t a, uint32_t b)
{
    return ((a - b) > ((uint32_t)(1) << 31));
}

bool Utils::overflow_less_than(uint64_t a, uint64_t b)
{
    return ((a - b) > ((uint64_t)(1) << 63));
}

int Utils::lock_and_write_pidfile(std::string filename)
{
  std::string lockfilename = filename + ".lock";
  int lockfd = open(lockfilename.c_str(),
                    O_WRONLY | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  int rc = flock(lockfd, LOCK_EX | LOCK_NB);
  if (rc == -1)
  {
    close(lockfd);
    return -1;
  }

  FILE* fd = fopen(filename.c_str(), "w");
  fprintf(fd, "%d\n", getpid());
  fclose(fd);

  return lockfd;
}
bool Utils::parse_stores_arg(const std::vector<std::string>& stores_arg,
                             const std::string& local_site_name,
                             std::string& local_store_location,
                             std::vector<std::string>& remote_stores_locations)
{
  if ((stores_arg.size() == 1) &&
      (stores_arg.front().find("=") == std::string::npos))
  {
    local_store_location = stores_arg.front();
  }
  else
  {
    for (std::vector<std::string>::const_iterator it = stores_arg.begin();
         it != stores_arg.end();
         ++it)
    {
      std::string site;
      std::string store;
      if (!split_site_store(*it, site, store))
      {
        return false;
      }
      else if (site == local_site_name)
      {
        local_store_location = store;
      }
      else
      {
        remote_stores_locations.push_back(store);
      }
    }
  }

  return true;
}
bool Utils::split_site_store(const std::string& site_store,
                             std::string& site,
                             std::string& store)
{
  size_t pos = site_store.find("=");
  if (pos == std::string::npos)
  {
    site = "";
    store = site_store;
    return false;
  }
  else
  {
    site = site_store.substr(0, pos);
    store = site_store.substr(pos+1);
    return true;
  }
}
bool Utils::parse_multi_site_stores_arg(const std::vector<std::string>& stores_arg,
                                        const std::string& local_site_name,
                                        const char* store_name,
                                        std::string& store_location,
                                        std::vector<std::string>& remote_stores_locations)
{
  if (!stores_arg.empty())
  {
    if (!Utils::parse_stores_arg(stores_arg,
                                 local_site_name,
                                 store_location,
                                 remote_stores_locations))
    {
      TRC_ERROR("Invalid format of %s program argument", store_name);
      return false;
    }

    if (store_location == "")
    {
      TRC_ERROR("No local site %s specified", store_name);
      return false;
    }
    else
    {
      TRC_INFO("Using %s", store_name);
      TRC_INFO("  Primary store: %s", store_location.c_str());
      std::string remote_stores_str = boost::algorithm::join(remote_stores_locations, ", ");
      TRC_INFO("  Backup store(s): %s", remote_stores_str.c_str());
    }
  }

  return true;
}

uint64_t Utils::get_time(clockid_t clock)
{
  struct timespec ts;
  clock_gettime(clock, &ts);
  uint64_t timestamp = ((uint64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
  return timestamp;
}

int Utils::daemonize()
{
  return daemonize("/dev/null", "/dev/null");
}

int Utils::daemonize(std::string out, std::string err)
{
  TRC_STATUS("Switching to daemon mode");

  // First fork
  pid_t pid = fork();
  if (pid == -1)
  {
    return errno;
  }
  else if (pid > 0)
  {
    exit(0);
  }

  if (freopen("/dev/null", "r", stdin) == NULL)
  {
    return errno;
  }
  if (freopen(out.c_str(), "a", stdout) == NULL)
  {
    return errno;
  }
  if (freopen(err.c_str(), "a", stderr) == NULL)
  {
    return errno;
  }
  if (setsid() == -1)
  {
    return errno;
  }

  umask(0);

  pid = fork();
  if (pid == -1)
  {
    return errno;
  }
  else if (pid > 0)
  {
    exit(0);
  }

  return 0;
}

void Utils::daemon_log_setup(int argc,
                             char* argv[],
                             bool daemon,
                             std::string& log_directory,
                             int log_level,
                             bool log_to_file)
{
  char* prog_name = argv[0];
  char* slash_ptr = rindex(argv[0], '/');
  if (slash_ptr != NULL)
  {
    prog_name = slash_ptr + 1;
  }

  std::string* syslog_identity = new std::string(prog_name);

  openlog(syslog_identity->c_str(), LOG_PID, LOG_LOCAL7);

  if (daemon)
  {
    int errnum;

    if (log_directory != "")
    {
      std::string prefix = log_directory + "/" + prog_name;
      errnum = Utils::daemonize(prefix + "_out.log",
                                prefix + "_err.log");
    }
    else
    {
      errnum = Utils::daemonize();
    }

    if (errnum != 0)
    {
      TRC_ERROR("Failed to convert to daemon, %d (%s)", errnum, strerror(errnum));
      exit(0);
    }
  }

  Log::setLoggingLevel(log_level);

  if ((log_to_file) && (log_directory != ""))
  {
    Log::setLogger(new Logger(log_directory, prog_name));
  }

  TRC_STATUS("Log level set to %d", log_level);
}

bool Utils::is_bracketed_address(const std::string& address)
{
  return ((address.size() >= 2) &&
          (address[0] == '[') &&
          (address[address.size() - 1] == ']'));
}

std::string Utils::remove_brackets_from_ip(std::string address)
{
  bool bracketed = is_bracketed_address(address);
  return bracketed ? address.substr(1, address.size() - 2) :
                     address;
}

std::string Utils::uri_address(std::string address, int default_port)
{
  Utils::IPAddressType addrtype = parse_ip_address(address);

  if (default_port == 0)
  {
    if (addrtype == IPAddressType::IPV6_ADDRESS)
    {
      address = "[" + address + "]";
    }
  }
  else
  {
    std::string port = std::to_string(default_port);

    if (addrtype == IPAddressType::IPV4_ADDRESS ||
        addrtype == IPAddressType::IPV6_ADDRESS_BRACKETED ||
        addrtype == IPAddressType::INVALID)
    {
      address = address + ":" + port;
    }
    else if (addrtype == IPAddressType::IPV6_ADDRESS)
    {
      address = "[" + address + "]:" + port;
    }
  }

  return address;
}

Utils::IPAddressType Utils::parse_ip_address(std::string address)
{
  std::string host;
  int port;
  bool with_port = Utils::split_host_port(address, host, port);

  host = with_port ? host : address;

  bool with_brackets = is_bracketed_address(host);

  host = with_brackets ? host.substr(1, host.size() - 2) : host;

  struct in_addr dummy_ipv4_addr;
  struct in6_addr dummy_ipv6_addr;

  if (inet_pton(AF_INET, host.c_str(), &dummy_ipv4_addr) == 1)
  {
    return (with_port) ? IPAddressType::IPV4_ADDRESS_WITH_PORT :
                         IPAddressType::IPV4_ADDRESS;
  }
  else if (inet_pton(AF_INET6, host.c_str(), &dummy_ipv6_addr) == 1)
  {
    return (with_port) ? IPAddressType::IPV6_ADDRESS_WITH_PORT :
                         ((with_brackets) ? IPAddressType::IPV6_ADDRESS_BRACKETED :
                                            IPAddressType::IPV6_ADDRESS);
  }
  else
  {
    return (with_port) ? IPAddressType::INVALID_WITH_PORT :
                         IPAddressType::INVALID;
  }
}

void Utils::calculate_diameter_timeout(int target_latency_us,
                                       int& diameter_timeout_ms)
{
  diameter_timeout_ms = std::ceil(target_latency_us/500);
}

bool Utils::in_vector(const std::string& element,
               const std::vector<std::string>& vec)
{
  return std::find(vec.begin(), vec.end(), element) != vec.end();
}


Utils::IOHook::IOHook(IOStartedCallback start_cb,
                      IOCompletedCallback complete_cb) :
  _io_started_cb(start_cb),
  _io_completed_cb(complete_cb)
{
  _hooks.push_back(this);
  TRC_DEBUG("Added IOHook %p to stack. There are now %d hooks", this, _hooks.size());
}

Utils::IOHook::~IOHook()
{
  _hooks.erase(std::remove(_hooks.begin(), _hooks.end(), this));
  TRC_DEBUG("Removed IOHook %p to stack. There are now %d hooks", this, _hooks.size());
}

void Utils::IOHook::io_starts(const std::string& reason)
{

  for(std::vector<IOHook*>::reverse_iterator hook = _hooks.rbegin();
      hook != _hooks.rend();
      hook++)
  {
    (*hook)->_io_started_cb(reason);
  }
}

void Utils::IOHook::io_completes(const std::string& reason)
{
  for(std::vector<IOHook*>::reverse_iterator hook = _hooks.rbegin();
      hook != _hooks.rend();
      hook++)
  {
    (*hook)->_io_completed_cb(reason);
  }
}

thread_local std::vector<Utils::IOHook*> Utils::IOHook::_hooks = {};

void Utils::IOMonitor::io_starts(const std::string& reason)
{
  _overt_io_depth++;
}

void Utils::IOMonitor::io_completes(const std::string& reason)
{
  _overt_io_depth--;
}

bool Utils::IOMonitor::thread_doing_overt_io()
{
  return _overt_io_depth != 0;
}

bool Utils::IOMonitor::thread_allows_covert_io()
{
  return _covert_io_allowed;
}

void Utils::IOMonitor::set_thread_allows_covert_io(bool allowed)
{
  _covert_io_allowed = allowed;
}

thread_local int Utils::IOMonitor::_overt_io_depth = 0;
thread_local bool Utils::IOMonitor::_covert_io_allowed = true;

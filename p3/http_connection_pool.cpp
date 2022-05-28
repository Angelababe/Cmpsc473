#include <atomic>
#include "utils.h"
#include "log.h"
#include "http_connection_pool.h"
#include "httpconnection.h"

HttpConnectionPool::HttpConnectionPool(LoadMonitor* load_monitor,
                                       SNMP::IPCountTable* stat_table,
                                       bool remote_connection,
                                       long timeout_ms,
                                       const std::string& source_address) :
  ConnectionPool<CURL*>(MAX_IDLE_TIME_S),
  _stat_table(stat_table),
  _connection_timeout_ms(remote_connection ? REMOTE_CONNECTION_LATENCY_MS :
                                             LOCAL_CONNECTION_LATENCY_MS),
  _source_address(source_address)
{
  if (timeout_ms != -1)
  {
    _timeout_ms = timeout_ms;
    TRC_STATUS("Connection pool will use override response timeout of %ldms", _timeout_ms);
  }
  else
  {
    _timeout_ms = calc_req_timeout_from_latency((load_monitor != NULL) ?
                                                              load_monitor->get_target_latency_us() :
                                                              DEFAULT_LATENCY_US);
    TRC_STATUS("Connection pool will use calculated response timeout of %ldms", _timeout_ms);
  }
}

CURL* HttpConnectionPool::create_connection(AddrInfo target)
{
  CURL* conn = curl_easy_init();
  TRC_DEBUG("Allocated CURL handle %p", conn);
  curl_easy_setopt(conn, CURLOPT_WRITEFUNCTION, &HttpClient::string_store);

  curl_easy_setopt(conn, CURLOPT_MAXCONNECTS, 1L);

  curl_easy_setopt(conn, CURLOPT_TIMEOUT_MS, _timeout_ms);

  curl_easy_setopt(conn,
                   CURLOPT_CONNECTTIMEOUT_MS,
                   _connection_timeout_ms);

  curl_easy_setopt(conn, CURLOPT_DNS_CACHE_TIMEOUT, 0L);

  curl_easy_setopt(conn, CURLOPT_TCP_NODELAY, 1L);

  curl_easy_setopt(conn, CURLOPT_NOSIGNAL, 1L);

  curl_easy_setopt(conn,
                   CURLOPT_DEBUGFUNCTION,
                   HttpClient::Recorder::debug_callback);

  curl_easy_setopt(conn, CURLOPT_VERBOSE, 1L);

  if (!_source_address.empty())
  {
    curl_easy_setopt(conn, CURLOPT_OPENSOCKETFUNCTION, &HttpConnectionPool::open_socket_fn);
    curl_easy_setopt(conn, CURLOPT_OPENSOCKETDATA, this);
  }

  increment_statistic(target, conn);

  return conn;
}

void HttpConnectionPool::increment_statistic(AddrInfo target, CURL* conn)
{
  if (_stat_table)
  {
    char buf[100];
    const char* ip_address = inet_ntop(target.address.af,
                                       &target.address.addr,
                                       buf,
                                       sizeof(buf));
    _stat_table->get(ip_address)->increment();
  }
}

void HttpConnectionPool::decrement_statistic(AddrInfo target, CURL* conn)
{
  if (_stat_table)
  {
    char buf[100];
    const char* ip_address = inet_ntop(target.address.af,
                                       &target.address.addr,
                                       buf,
                                       sizeof(buf));
    if (_stat_table->get(ip_address)->decrement() == 0)
    {
    }
  }
}

void HttpConnectionPool::destroy_connection(AddrInfo target, CURL* conn)
{
  decrement_statistic(target, conn);
  curl_slist *host_resolve = NULL;
  curl_easy_getinfo(conn, CURLINFO_PRIVATE, &host_resolve);
  if (host_resolve != NULL)
  {
    curl_easy_setopt(conn, CURLOPT_PRIVATE, NULL);
    curl_slist_free_all(host_resolve);
  }

  curl_easy_cleanup(conn);
}

void HttpConnectionPool::release_connection(ConnectionInfo<CURL*>* conn_info,
                                            bool return_to_pool)
{
  if (return_to_pool)
  {
    CURL* conn = conn_info->conn;
    curl_easy_setopt(conn, CURLOPT_HTTPHEADER, NULL);
    curl_easy_setopt(conn, CURLOPT_CUSTOMREQUEST, NULL);
    curl_easy_setopt(conn, CURLOPT_WRITEHEADER, NULL);
    curl_easy_setopt(conn, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(conn, CURLOPT_HEADERFUNCTION, NULL);
    curl_easy_setopt(conn, CURLOPT_POST, 0);
  }
  ConnectionPool<CURL*>::release_connection(conn_info, return_to_pool);
}

long HttpConnectionPool::calc_req_timeout_from_latency(int latency_us)
{
  return _connection_timeout_ms + std::max(1, (latency_us * TIMEOUT_LATENCY_MULTIPLIER) / 1000);
}

curl_socket_t HttpConnectionPool::open_socket_fn(void *clientp,
                                                 curlsocktype purpose,
                                                 struct curl_sockaddr *address)
{
  HttpConnectionPool* pool = static_cast<HttpConnectionPool*>(clientp);
  return pool->open_socket(purpose, address);
}

curl_socket_t HttpConnectionPool::open_socket(curlsocktype purpose,
                                              struct curl_sockaddr *address)
{
  int fd = socket(address->family, address->socktype, address->protocol);

  if (fd <= 0)
  {
    TRC_ERROR("Error creating socket %d (%s)", errno, strerror(errno));
    return -1;
  }

  TRC_DEBUG("Bind socket %d to address %s", fd, _source_address.c_str());

  struct sockaddr_storage sa_storage = {0};
  size_t sa_size = 0;
  int rc;

  if (address->family == AF_INET)
  {
    struct sockaddr_in* sa = (struct sockaddr_in*)&sa_storage;
    sa_size = sizeof(*sa);

    sa->sin_family = address->family;
    rc = inet_pton(address->family, _source_address.c_str(), &sa->sin_addr);
  }
  else
  {
    struct sockaddr_in6* sa = (struct sockaddr_in6*)&sa_storage;
    sa_size = sizeof(*sa);

    sa->sin6_family = address->family;
    rc = inet_pton(address->family, _source_address.c_str(), &sa->sin6_addr);
  }

  if (rc == 1)
  {
    rc = bind(fd, (const struct sockaddr*)&sa_storage, sa_size);

    if (rc != 0)
    {
      TRC_ERROR("Error %d (%s) trying to bind to address %s in family %d",
                errno, strerror(errno), _source_address.c_str(), address->family);
      return -1;
    }
  }
  else
  {
    TRC_ERROR("inet_pton() returned %d when parsing address %s in family %d",
              rc, _source_address.c_str(), address->family);
    return -1;
  }

  return fd;
}

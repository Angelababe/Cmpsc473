#include <atomic>
#include "memcached_connection_pool.h"

memcached_st* MemcachedConnectionPool::create_connection(AddrInfo target)
{
  memcached_st* conn = memcached(_options.c_str(), _options.length());
  memcached_behavior_set(conn,
                         MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT,
                         _max_connect_latency_ms);

  memcached_behavior_set(conn,
                         MEMCACHED_BEHAVIOR_TCP_NODELAY,
                         true);

  std::string address = target.address.to_string();

  CW_IO_STARTS("Memcached Server Add for " + address)
  {
    memcached_server_add(conn, address.c_str(), target.port);
  }
  CW_IO_COMPLETES()

  return conn;
}

void MemcachedConnectionPool::destroy_connection(AddrInfo target, memcached_st* conn)
{
  memcached_free(conn);
}

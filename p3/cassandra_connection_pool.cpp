#include <atomic>
#include "utils.h"
#include "log.h"
#include "cassandra_connection_pool.h"
#include "cassandra_store.h"

namespace CassandraStore
{

static const int TSOCKET_CONN_TIMEOUT_MS = 250;
static const int TSOCKET_RECV_TIMEOUT_MS = 250;
static const int TSOCKET_SEND_TIMEOUT_MS = 250;

static const double MAX_IDLE_TIME_S = 60;

CassandraConnectionPool::CassandraConnectionPool() :
  ConnectionPool<Client*>(MAX_IDLE_TIME_S, true)
{
}

Client* CassandraConnectionPool::create_connection(AddrInfo target)
{
  char buf[100];
  const char *remote_ip = inet_ntop(target.address.af,
                                    &target.address.addr,
                                    buf,
                                    sizeof(buf));

  boost::shared_ptr<TSocket> socket =
    boost::shared_ptr<TSocket>(new TSocket(std::string(remote_ip), target.port));
  socket->setConnTimeout(TSOCKET_CONN_TIMEOUT_MS);
  socket->setRecvTimeout(TSOCKET_RECV_TIMEOUT_MS);
  socket->setSendTimeout(TSOCKET_SEND_TIMEOUT_MS);
  boost::shared_ptr<TFramedTransport> transport =
    boost::shared_ptr<TFramedTransport>(new TFramedTransport(socket));
  boost::shared_ptr<TProtocol> protocol =
     boost::shared_ptr<TBinaryProtocol>(new TBinaryProtocol(transport));

  return new RealThriftClient(protocol, transport);
}

void CassandraConnectionPool::destroy_connection(AddrInfo target, Client* conn)
{
  delete conn; conn = NULL;
}

} 

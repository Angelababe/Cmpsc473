#include <atomic>
#include "utils.h"
#include "log.h"
#include <boost/format.hpp>
#include <time.h>

#include "cassandra_store.h"
#include "sasevent.h"
#include "sas.h"

using namespace apache::thrift;
using namespace apache::thrift::transport;
using namespace apache::thrift::protocol;
using namespace org::apache::cassandra;

namespace CassandraStore
{
const int32_t GET_SLICE_MAX_COLUMNS = 1000000;

class NoOperation : public Operation
{
public:
  bool perform(Client* client, SAS::TrailId trail)
  {
    return true;
  }
};


HAOperation::HAOperation() :
  _consistency_two_tried(false)
{
}
#define HA(CLIENT, METHOD, TRAIL_ID, ...)                                      \
        bool success = false;                                                  \
        if (!_consistency_two_tried)                                           \
        {                                                                      \
          _consistency_two_tried = true;                                       \
          try                                                                  \
          {                                                                    \
            CLIENT->METHOD(__VA_ARGS__, ConsistencyLevel::TWO);                \
            success = true;                                                    \
          }                                                                    \
          catch(UnavailableException& ue)                                      \
          {                                                                    \
            TRC_DEBUG("Failed TWO read for %s. Try ONE", #METHOD);             \
            int event_id = SASEvent::CASS_REQUEST_TWO_FAIL;                    \
            SAS::Event event(TRAIL_ID, event_id, 0);                           \
            SAS::report_event(event);                                          \
          }                                                                    \
          catch(TimedOutException& te)                                         \
          {                                                                    \
            TRC_DEBUG("Failed TWO read for %s. Try ONE", #METHOD);             \
            int event_id = SASEvent::CASS_REQUEST_TWO_FAIL;                    \
            SAS::Event event(TRAIL_ID, event_id, 1);                           \
            SAS::report_event(event);                                          \
          }                                                                    \
        }                                                                      \
        if (!success)                                                          \
        {                                                                      \
          CLIENT->METHOD(__VA_ARGS__, ConsistencyLevel::ONE);                  \
        }

void HAOperation::
ha_get_columns(Client* client,
               const std::string& column_family,
               const std::string& key,
               const std::vector<std::string>& names,
               std::vector<cass::ColumnOrSuperColumn>& columns,
               SAS::TrailId trail)
{
  HA(client, get_columns, trail, column_family, key, names, columns);
}

void HAOperation::
ha_get_columns_with_prefix(Client* client,
                           const std::string& column_family,
                           const std::string& key,
                           const std::string& prefix,
                           std::vector<ColumnOrSuperColumn>& columns,
                           SAS::TrailId trail)
{
  HA(client, get_columns_with_prefix, trail, column_family, key, prefix, columns);
}


void HAOperation::
ha_multiget_columns_with_prefix(Client* client,
                                const std::string& column_family,
                                const std::vector<std::string>& keys,
                                const std::string& prefix,
                                std::map<std::string, std::vector<ColumnOrSuperColumn> >& columns,
                                SAS::TrailId trail)
{
  HA(client, multiget_columns_with_prefix, trail, column_family, keys, prefix, columns);
}

void HAOperation::
ha_get_all_columns(Client* client,
                   const std::string& column_family,
                   const std::string& key,
                   std::vector<ColumnOrSuperColumn>& columns,
                   SAS::TrailId trail)
{
  HA(client, get_row, trail, column_family, key, columns);
}

RealThriftClient::RealThriftClient(boost::shared_ptr<TProtocol> prot,
                                   boost::shared_ptr<TFramedTransport> transport) :
  _cass_client(prot),
  _transport(transport),
  _connected(false)
{
}

RealThriftClient::~RealThriftClient()
{
  _transport->close();
}

bool RealThriftClient::is_connected()
{
  return _connected;
}

void RealThriftClient::connect()
{
  _transport->open();
  _connected = true;
}

void RealThriftClient::set_keyspace(const std::string& keyspace)
{
  _cass_client.set_keyspace(keyspace);
}

void RealThriftClient::batch_mutate(const std::map<std::string, std::map<std::string, std::vector<cass::Mutation> > >& mutation_map,
                                    const cass::ConsistencyLevel::type consistency_level)
{
  _cass_client.batch_mutate(mutation_map, consistency_level);
}

void RealThriftClient::get_slice(std::vector<cass::ColumnOrSuperColumn>& _return,
                                 const std::string& key,
                                 const cass::ColumnParent& column_parent,
                                 const cass::SlicePredicate& predicate,
                                 const cass::ConsistencyLevel::type consistency_level)
{
  _cass_client.get_slice(_return, key, column_parent, predicate, consistency_level);
}

void RealThriftClient::multiget_slice(std::map<std::string, std::vector<cass::ColumnOrSuperColumn> >& _return,
                                      const std::vector<std::string>& keys,
                                      const cass::ColumnParent& column_parent,
                                      const cass::SlicePredicate& predicate,
                                      const cass::ConsistencyLevel::type consistency_level)
{
  _cass_client.multiget_slice(_return, keys, column_parent, predicate, consistency_level);
}

void RealThriftClient::remove(const std::string& key,
                              const cass::ColumnPath& column_path,
                              const int64_t timestamp,
                              const cass::ConsistencyLevel::type consistency_level)
{
  _cass_client.remove(key, column_path, timestamp, consistency_level);
}

void RealThriftClient::get_range_slices(std::vector<KeySlice> & _return,
                                        const ColumnParent& column_parent,
                                        const SlicePredicate& predicate,
                                        const KeyRange& range,
                                        const ConsistencyLevel::type consistency_level)
{
  _cass_client.get_range_slices(_return, column_parent, predicate, range, consistency_level);
}


int64_t Store::generate_timestamp()
{
  timespec clock_time;
  int64_t timestamp;

  clock_gettime(CLOCK_REALTIME, &clock_time);
  timestamp = clock_time.tv_sec;
  timestamp *= 1000000;
  timestamp += (clock_time.tv_nsec / 1000);

  TRC_DEBUG("Generated Cassandra timestamp %llu", timestamp);
  return timestamp;
}


Store::Store(const std::string& keyspace) :
  _keyspace(keyspace),
  _cass_hostname(""),
  _cass_port(0),
  _num_threads(0),
  _max_queue(0),
  _thread_pool(NULL),
  _comm_monitor(NULL),
  _conn_pool(new CassandraConnectionPool())
{
}

void Store::configure_connection(std::string cass_hostname,
                                 uint16_t cass_port,
                                 BaseCommunicationMonitor* comm_monitor,
                                 CassandraResolver* resolver)
{
  TRC_STATUS("Configuring store connection");
  TRC_STATUS("  Hostname:  %s", cass_hostname.c_str());
  TRC_STATUS("  Port:      %u", cass_port);
  _cass_hostname = cass_hostname;
  _cass_port = cass_port;
  _comm_monitor = comm_monitor;
  _resolver = resolver;
}


ResultCode Store::connection_test()
{
  TRC_DEBUG("Testing cassandra connection");

  ResultCode rc = UNKNOWN_ERROR;
  std::string cass_error_text = "";

  NoOperation no_op;
  perform_op(&no_op, 0, rc, cass_error_text);
  return rc;
}


void Store::configure_workers(ExceptionHandler* exception_handler,
                              unsigned int num_threads,
                              unsigned int max_queue)
{
  TRC_STATUS("Configuring store worker pool");
  TRC_STATUS("  Threads:   %u", num_threads);
  TRC_STATUS("  Max Queue: %u", max_queue);
  _exception_handler = exception_handler;
  _num_threads = num_threads;
  _max_queue = max_queue;
}
ResultCode Store::start()
{
  ResultCode rc = OK;
  TRC_STATUS("Starting store");
  if (_num_threads > 0)
  {
    _thread_pool = new Pool(this,
                            _num_threads,
                            _exception_handler,
                            _max_queue);

    if (!_thread_pool->start())
    {
      rc = RESOURCE_ERROR; 
    }
  }

  return rc;
}


void Store::stop()
{
  TRC_STATUS("Stopping store");
  if (_thread_pool != NULL)
  {
    _thread_pool->stop();
  }
}
void Store::wait_stopped()
{
  TRC_STATUS("Waiting for store to stop");
  if (_thread_pool != NULL)
  {
    _thread_pool->join();

    delete _thread_pool; _thread_pool = NULL;
  }
}
Store::~Store()
{
  if (_thread_pool != NULL)
  {
    stop();
    wait_stopped();
  }

  delete _conn_pool; _conn_pool = NULL;
}


bool Store::perform_op(Operation* op,
                       SAS::TrailId trail,
                       ResultCode& cass_result,
                       std::string& cass_error_text)
{
  bool success = false;
  bool retry = true;
  int attempt_count = 0;
  BaseAddrIterator* target_it = _resolver->resolve_iter(_cass_hostname,
                                                        _cass_port,
                                                        trail);
  AddrInfo target;
  while (retry &&
         (attempt_count < 2) &&
         (target_it->next(target) || (attempt_count == 1)))
  {
    cass_result = OK;
    attempt_count++;
    retry = false;
    ConnectionHandle<Client*> conn_handle = _conn_pool->get_connection(target);
    try
    {
      Client* client = conn_handle.get_connection();

      if (!client->is_connected())
      {
        TRC_DEBUG("Connecting to %s", target.to_string().c_str());
        client->connect();
        client->set_keyspace(_keyspace);
      }

      success = op->perform(client, trail);
    }
    catch(TTransportException& te)
    {
      cass_result = CONNECTION_ERROR;
      cass_error_text = (boost::format("Exception: %s [%d]")
                         % te.what() % te.getType()).str();
      SAS::Event event(trail, SASEvent::CASS_CONNECT_FAIL, 0);
      event.add_var_param(cass_error_text);
      SAS::report_event(event);
      conn_handle.set_return_to_pool(false);

      TRC_DEBUG("Error connecting to Cassandra - retrying if possible");
      retry = true;
    }
    catch(TimedOutException& te)
    {
      cass_result = TIMEOUT;
      cass_error_text = (boost::format("Exception: %s")
                         % te.what()).str();
      SAS::Event event(trail, SASEvent::CASS_TIMEOUT, 0);
      SAS::report_event(event);

      TRC_DEBUG("Cassandra timeout - retrying if possible");
      retry = true;
    }
    catch(InvalidRequestException& ire)
    {
      cass_result = INVALID_REQUEST;
      cass_error_text = (boost::format("Exception: %s [%s]")
                         % ire.what() % ire.why.c_str()).str();
    }
    catch(NotFoundException& nfe)
    {
      cass_result = NOT_FOUND;
      cass_error_text = (boost::format("Exception: %s")
                         % nfe.what()).str();
    }
    catch(RowNotFoundException& nre)
    {
      cass_result = NOT_FOUND;
      cass_error_text = (boost::format("Row %s not present in column_family %s")
                         % nre.key % nre.column_family).str();
    }
    catch(UnavailableException& ue)
    {
      cass_result = UNAVAILABLE;
      cass_error_text = (boost::format("Exception: %s")
                         % ue.what()).str();
    }
    catch(...)
    {
      cass_result = UNKNOWN_ERROR;
      cass_error_text = "Unknown error";
    }
    if (cass_result == CONNECTION_ERROR)
    {
      _resolver->blacklist(target);
    }
    else
    {
      _resolver->success(target);
    }
  }

  return success;
}


bool Store::do_sync(Operation* op, SAS::TrailId trail)
{
  ResultCode cass_result = UNKNOWN_ERROR;
  std::string cass_error_text = "";
  bool success  = perform_op(op, trail, cass_result, cass_error_text);

  if (cass_result == OK)
  {
    if (_comm_monitor)
    {
      _comm_monitor->inform_success();
    }
  }
  else
  {
    if (_comm_monitor)
    {
      if (cass_result == CONNECTION_ERROR)
      {
        _comm_monitor->inform_failure();
      }
      else
      {
        _comm_monitor->inform_success();
      }
    }

    if (cass_result == NOT_FOUND)
    {
      TRC_DEBUG("Cassandra request failed: rc=%d, %s",
                cass_result, cass_error_text.c_str());
    }
    else
    {
      TRC_ERROR("Cassandra request failed: rc=%d, %s",
                cass_result, cass_error_text.c_str());

    }

    op->unhandled_exception(cass_result, cass_error_text, trail);
  }

  return success;
}


void Store::do_async(Operation*& op, Transaction*& trx)
{
  if (_thread_pool == NULL)
  {
    TRC_ERROR("Can't process async operation as no thread pool has been configured");
    assert(!"Can't process async operation as no thread pool has been configured");
  }

  std::pair<Operation*, Transaction*> params(op, trx);
  _thread_pool->add_work(params);
  op = NULL;
  trx = NULL;
}
Store::Pool::Pool(Store* store,
                  unsigned int num_threads,
                  ExceptionHandler* exception_handler,
                  unsigned int max_queue) :
  ThreadPool<std::pair<Operation*, Transaction*> >(num_threads,
                                                   exception_handler,
                                                   exception_callback,
                                                   max_queue),
  _store(store)
{}


Store::Pool::~Pool() {}


void Store::Pool::process_work(std::pair<Operation*, Transaction*>& params)
{
  bool success = false;
  Operation* op = params.first;
  Transaction* trx = params.second;
  try
  {
    trx->start_timer();
    success = _store->do_sync(op, trx->trail);
  }
  catch(...)
  {
    TRC_ERROR("Unhandled exception when processing cassandra request");
  }
  trx->stop_timer();
  if (success)
  {
    trx->on_success(op);
  }
  else
  {
    trx->on_failure(op);
  }
  delete trx; trx = NULL;
  delete op; op = NULL;
}
Operation::Operation() : _cass_status(OK), _cass_error_text() {}

ResultCode Operation::get_result_code()
{
  return _cass_status;
}


std::string Operation::get_error_text()
{
  return _cass_error_text;
}


void Operation::unhandled_exception(ResultCode rc,
                                    std::string& description,
                                    SAS::TrailId trail)
{
  _cass_status = rc;
  _cass_error_text = description;
}


void Client::
put_columns(const std::string& column_family,
            const std::vector<std::string>& keys,
            const std::map<std::string, std::string>& columns,
            int64_t timestamp,
            int32_t ttl,
            cass::ConsistencyLevel::type consistency_level)
{
  std::vector<Mutation> mutations;
  std::map<std::string, std::map<std::string, std::vector<Mutation> > > mutmap;
  TRC_DEBUG("Constructing cassandra put request with timestamp %lld and per-column TTLs", timestamp);
  for (std::map<std::string, std::string>::const_iterator it = columns.begin();
       it != columns.end();
       ++it)
  {
    Mutation mutation;
    Column* column = &mutation.column_or_supercolumn.column;

    column->name = it->first;
    column->value = it->second;
    TRC_DEBUG("  %s => %s (TTL %d)", column->name.c_str(), column->value.c_str(), ttl);
    column->__isset.value = true;
    column->timestamp = timestamp;
    column->__isset.timestamp = true;
    if (ttl > 0)
    {
      column->ttl = ttl;
      column->__isset.ttl = true;
    }

    mutation.column_or_supercolumn.__isset.column = true;
    mutation.__isset.column_or_supercolumn = true;
    mutations.push_back(mutation);
  }
  for (std::vector<std::string>::const_iterator it = keys.begin();
       it != keys.end();
       ++it)
  {
    mutmap[*it][column_family] = mutations;
  }
  TRC_DEBUG("Executing put request operation");
  batch_mutate(mutmap, consistency_level);
}


void Client::
put_columns(const std::vector<RowColumns>& to_put,
            int64_t timestamp,
            int32_t ttl)
{
  std::map<std::string, std::map<std::string, std::vector<Mutation> > > mutmap;
  TRC_DEBUG("Constructing cassandra put request with timestamp %lld and per-column TTLs", timestamp);
  for (std::vector<RowColumns>::const_iterator it = to_put.begin();
       it != to_put.end();
       ++it)
  {
    std::vector<Mutation> mutations;

    for (std::map<std::string, std::string>::const_iterator col = it->columns.begin();
         col != it->columns.end();
         ++col)
    {
      Mutation mutation;
      Column* column = &mutation.column_or_supercolumn.column;

      column->name = col->first;
      column->value = col->second;
      TRC_DEBUG("  %s => %s (TTL %d)", column->name.c_str(), column->value.c_str(), ttl);
      column->__isset.value = true;
      column->timestamp = timestamp;
      column->__isset.timestamp = true;
      if (ttl > 0)
      {
        column->ttl = ttl;
        column->__isset.ttl = true;
      }

      mutation.column_or_supercolumn.__isset.column = true;
      mutation.__isset.column_or_supercolumn = true;
      mutations.push_back(mutation);
    }

    mutmap[it->key][it->cf] = mutations;
  }
  TRC_DEBUG("Executing put request operation");
  batch_mutate(mutmap, ConsistencyLevel::ONE);
}


void Client::
get_columns(const std::string& column_family,
            const std::string& key,
            const std::vector<std::string>& names,
            std::vector<ColumnOrSuperColumn>& columns,
            ConsistencyLevel::type consistency_level)
{
  SlicePredicate sp;
  sp.column_names = names;
  sp.__isset.column_names = true;

  issue_get_for_key(column_family, key, sp, columns, consistency_level);
}


void Client::
get_columns_with_prefix(const std::string& column_family,
                        const std::string& key,
                        const std::string& prefix,
                        std::vector<ColumnOrSuperColumn>& columns,
                        ConsistencyLevel::type consistency_level)
{
  SliceRange sr;
  sr.start = prefix;
  sr.finish = prefix;
  *sr.finish.rbegin() = (*sr.finish.rbegin() + 1);
  sr.count = GET_SLICE_MAX_COLUMNS;

  SlicePredicate sp;
  sp.slice_range = sr;
  sp.__isset.slice_range = true;

  issue_get_for_key(column_family, key, sp, columns, consistency_level);
  for (std::vector<ColumnOrSuperColumn>::iterator it = columns.begin();
       it != columns.end();
       ++it)
  {
    it->column.name = it->column.name.substr(prefix.length());
  }
}


void Client::
multiget_columns_with_prefix(const std::string& column_family,
                             const std::vector<std::string>& keys,
                             const std::string& prefix,
                             std::map<std::string, std::vector<ColumnOrSuperColumn> >& columns,
                             ConsistencyLevel::type consistency_level)
{
  SliceRange sr;
  sr.start = prefix;
  sr.finish = prefix;
  *sr.finish.rbegin() = (*sr.finish.rbegin() + 1);
  sr.count = GET_SLICE_MAX_COLUMNS;

  SlicePredicate sp;
  sp.slice_range = sr;
  sp.__isset.slice_range = true;

  issue_multiget_for_key(column_family, keys, sp, columns, consistency_level);

  for (std::map<std::string, std::vector<ColumnOrSuperColumn> >::iterator it = columns.begin();
       it != columns.end();
       ++it)
  {
    for (std::vector<ColumnOrSuperColumn>::iterator it2 = it->second.begin();
         it2 != it->second.end();
         ++it2)
    {
      it2->column.name = it2->column.name.substr(prefix.length());
    }
  }
}


void Client::
get_row(const std::string& column_family,
        const std::string& key,
        std::vector<ColumnOrSuperColumn>& columns,
        ConsistencyLevel::type consistency_level)
{
  SliceRange sr;
  sr.start = "";
  sr.finish = "";
  sr.count = GET_SLICE_MAX_COLUMNS;

  SlicePredicate sp;
  sp.slice_range = sr;
  sp.__isset.slice_range = true;

  issue_get_for_key(column_family, key, sp, columns, consistency_level);
}


void Client::
issue_get_for_key(const std::string& column_family,
                  const std::string& key,
                  const SlicePredicate& predicate,
                  std::vector<ColumnOrSuperColumn>& columns,
                  ConsistencyLevel::type consistency_level)
{
  ColumnParent cparent;
  cparent.column_family = column_family;

  get_slice(columns, key, cparent, predicate, consistency_level);

  if (columns.size() == 0)
  {
    RowNotFoundException row_not_found_ex(column_family, key);
    throw row_not_found_ex;
  }
}


void Client::
issue_multiget_for_key(const std::string& column_family,
                       const std::vector<std::string>& keys,
                       const SlicePredicate& predicate,
                       std::map<std::string, std::vector<ColumnOrSuperColumn> >& columns,
                       ConsistencyLevel::type consistency_level)
{
  ColumnParent cparent;
  cparent.column_family = column_family;

  multiget_slice(columns, keys, cparent, predicate, consistency_level);

  if (columns.size() == 0)
  {
    RowNotFoundException row_not_found_ex(column_family, keys.front());
    throw row_not_found_ex;
  }
}


void Client::
delete_row(const std::string& column_family,
           const std::string& key,
           int64_t timestamp)
{
  ColumnPath cp;
  cp.column_family = column_family;

  TRC_DEBUG("Deleting row with key %s (timestamp %lld", key.c_str(), timestamp);
  remove(key, cp, timestamp, ConsistencyLevel::ONE);
}


void Client::
delete_columns(const std::vector<RowColumns>& to_rm,
               int64_t timestamp)
{
  std::map<std::string, std::map<std::string, std::vector<Mutation> > > mutmap;

  TRC_DEBUG("Constructing cassandra delete request with timestamp %lld", timestamp);
  for (std::vector<RowColumns>::const_iterator it = to_rm.begin();
       it != to_rm.end();
       ++it)
  {
    if (it->columns.empty())
    {
      TRC_DEBUG("Deleting row %s:%s", it->cf.c_str(), it->key.c_str());
      ColumnPath cp;
      cp.column_family = it->cf;

      remove(it->key, cp, timestamp, ConsistencyLevel::ONE);
    }
    else
    {
      std::vector<Mutation> mutations;
      Mutation mutation;
      Deletion deletion;
      SlicePredicate what;

      std::vector<std::string> column_names;

      for (std::map<std::string, std::string>::const_iterator col = it->columns.begin();
           col != it->columns.end();
           ++col)
      {
        column_names.push_back(col->first);
      }

      what.__set_column_names(column_names);
      TRC_DEBUG("Deleting %d columns from %s:%s", what.column_names.size(), it->cf.c_str(), it->key.c_str());

      deletion.__set_predicate(what);
      deletion.__set_timestamp(timestamp);
      mutation.__set_deletion(deletion);
      mutations.push_back(mutation);

      mutmap[it->key][it->cf] = mutations;
    }
  }

  if (!mutmap.empty()) {
    TRC_DEBUG("Executing delete request operation");
    batch_mutate(mutmap, ConsistencyLevel::ONE);
  }
}

void Client::
delete_slice(const std::string& column_family,
             const std::string& key,
             const std::string& start,
             const std::string& finish,
             const int64_t timestamp)
{
  std::map<std::string, std::map<std::string, std::vector<Mutation> > > mutmap;
  Mutation mutation;
  Deletion deletion;
  SlicePredicate predicate;
  SliceRange range;

  range.__set_start(start);
  range.__set_finish(finish);
  predicate.__set_slice_range(range);
  deletion.__set_predicate(predicate);
  deletion.__set_timestamp(timestamp);
  mutation.__set_deletion(deletion);

  mutmap[key][column_family].push_back(mutation);
  batch_mutate(mutmap, ConsistencyLevel::ONE);
}


bool find_column_value(std::vector<cass::ColumnOrSuperColumn> cols,
                                  const std::string& name,
                                  std::string& value)
{
  for (std::vector<ColumnOrSuperColumn>::const_iterator it = cols.begin();
       it != cols.end();
       ++it)
  {
    if ((it->__isset.column) && (it->column.name == name))
    {
      value = it->column.value;
      return true;
    }
  }
  return false;
}

}

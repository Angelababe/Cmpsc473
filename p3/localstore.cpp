#include <atomic>
#include <cassert>
#include <map>
#include <list>
#include <string>

#include <time.h>
#include <stdint.h>

#include "log.h"
#include "localstore.h"


LocalStore::LocalStore() :
  _data_contention_flag(false),
  _db_lock(PTHREAD_MUTEX_INITIALIZER),
  _db(),
  _force_error_on_set_flag(false),
  _force_error_on_get_flag(false),
  _force_error_on_delete_flag(false),
  _old_db()
{
  TRC_DEBUG("Created local store");
}


LocalStore::~LocalStore()
{
  flush_all();
  pthread_mutex_destroy(&_db_lock);
}


void LocalStore::flush_all()
{
  pthread_mutex_lock(&_db_lock);
  TRC_DEBUG("Flushing local store");
  _db.clear();
  _old_db.clear();
  pthread_mutex_unlock(&_db_lock);
}

void LocalStore::force_contention()
{
  TRC_DEBUG("Setting _data_contention_flag");
  _data_contention_flag = true;
}

void LocalStore::force_error()
{
  _force_error_on_set_flag = true;
}

void LocalStore::force_delete_error()
{
  _force_error_on_delete_flag = true;
}

void LocalStore::force_get_error()
{
  _force_error_on_get_flag = true;
}

Store::Status LocalStore::get_data(const std::string& table,
                                   const std::string& key,
                                   std::string& data,
                                   uint64_t& cas,
                                   SAS::TrailId trail,
                                   bool log_body,
                                   Format data_format)
{
  TRC_DEBUG("get_data table=%s key=%s", table.c_str(), key.c_str());
  Store::Status status = Store::Status::NOT_FOUND;

  if (_force_error_on_get_flag)
  {
    TRC_DEBUG("Force an error on the GET");
    _force_error_on_get_flag = false;
    return Store::Status::ERROR;
  }

  std::string fqkey = table + "\\\\" + key;

  pthread_mutex_lock(&_db_lock);

  std::map<std::string, Record>& _db_in_use = _data_contention_flag ? _old_db : _db;
  if (_data_contention_flag)
  {
    _data_contention_flag = false;
  }

  uint32_t now = time(NULL);

  TRC_DEBUG("Search store for key %s", fqkey.c_str());

  std::map<std::string, Record>::iterator i = _db_in_use.find(fqkey);
  if (i != _db_in_use.end())
  {
    Record& r = i->second;
    TRC_DEBUG("Found record, expiry = %ld (now = %ld)", r.expiry, now);
    if (r.expiry < now)
    {
      TRC_DEBUG("Record has expired, remove it from store");
      _db_in_use.erase(i);
    }
    else
    {
      TRC_DEBUG("Record has not expired, return %d bytes of data with CAS = %ld",
                r.data.length(), r.cas);
      data = r.data;
      cas = r.cas;
      status = Store::Status::OK;
    }
  }

  pthread_mutex_unlock(&_db_lock);

  TRC_DEBUG("get_data status = %d", status);

  return status;
}


Store::Status LocalStore::set_data_without_cas(const std::string& table,
                                               const std::string& key,
                                               const std::string& data,
                                               int expiry,
                                               SAS::TrailId trail,
                                               bool log_body,
                                               Store::Format data_format)
{
  TRC_DEBUG("set_data_without_cas table=%s key=%s expiry=%d",
            table.c_str(), key.c_str(), expiry);

  return set_data_inner(table, key, data, 0, false, expiry, trail);
}

Store::Status LocalStore::set_data(const std::string& table,
                                   const std::string& key,
                                   const std::string& data,
                                   uint64_t cas,
                                   int expiry,
                                   SAS::TrailId trail,
                                   bool log_body,
                                   Store::Format data_format)
{
  TRC_DEBUG("set_data table=%s key=%s CAS=%ld expiry=%d",
            table.c_str(), key.c_str(), cas, expiry);

  return set_data_inner(table, key, data, cas, true, expiry, trail);
}

Store::Status LocalStore::set_data_inner(const std::string& table,
                                         const std::string& key,
                                         const std::string& data,
                                         uint64_t cas,
                                         bool check_cas,
                                         int expiry,
                                         SAS::TrailId trail)
{
  Store::Status status = Store::Status::DATA_CONTENTION;

  if (data.length() > Store::MAX_DATA_LENGTH)
  {
    TRC_WARNING("Attempting to write more than %lu bytes of data -- reject request",
                Store::MAX_DATA_LENGTH);
    return Store::Status::ERROR;
  }

  if (_force_error_on_set_flag)
  {
    TRC_DEBUG("Force an error on the SET");
    _force_error_on_set_flag = false;

    return Store::Status::ERROR;
  }

  std::string fqkey = table + "\\\\" + key;

  pthread_mutex_lock(&_db_lock);

  uint32_t now = time(NULL);

  TRC_DEBUG("Search store for key %s", fqkey.c_str());

  std::map<std::string, Record>::iterator i = _db.find(fqkey);

  if (i != _db.end())
  {
    Record& r = i->second;
    TRC_DEBUG("Found existing record, CAS = %lu, expiry = %u (now = %u)",
              r.cas, r.expiry, now);

    if ((!check_cas) ||
        (((r.expiry >= now) && (cas == r.cas)) ||
         ((r.expiry < now) && (cas == 0))))
    {
      _old_db[fqkey] = r;

      r.data = data;
      r.cas = check_cas ? ++cas : (r.cas + 1);
      r.expiry = (expiry == 0) ? 0 : (uint32_t)expiry + now;
      status = Store::Status::OK;
      TRC_DEBUG("CAS is consistent, updated record, CAS = %lu, expiry = %u (now = %u)",
                r.cas, r.expiry, now);
    }
  }
  else if (cas == 0)
  {
    Record& r = _db[fqkey];
    r.data = data;
    r.cas = 1;
    r.expiry = (expiry == 0) ? 0 : (uint32_t)expiry + now;
    status = Store::Status::OK;
    TRC_DEBUG("No existing record so inserted new record, CAS = %lu, expiry = %u (now = %u)",
              r.cas, r.expiry, now);
  }

  pthread_mutex_unlock(&_db_lock);
  return status;
}

Store::Status LocalStore::delete_data(const std::string& table,
                                      const std::string& key,
                                      SAS::TrailId trail)
{
  TRC_DEBUG("delete_data table=%s key=%s",
            table.c_str(), key.c_str());

  if (_force_error_on_delete_flag)
  {
    TRC_DEBUG("Force an error on the DELETE");
    _force_error_on_delete_flag = false;

    return Store::Status::ERROR;
  }

  Store::Status status = Store::Status::OK;

  std::string fqkey = table + "\\\\" + key;

  pthread_mutex_lock(&_db_lock);

  _db.erase(fqkey);

  pthread_mutex_unlock(&_db_lock);

  return status;
}

void LocalStore::swap_dbs(LocalStore* rhs)
{
  pthread_mutex_lock(&_db_lock);
  pthread_mutex_lock(&rhs->_db_lock);

  std::swap(_db, rhs->_db);
  std::swap(_old_db, rhs->_old_db);

  pthread_mutex_unlock(&rhs->_db_lock);
  pthread_mutex_unlock(&_db_lock);
}


#include <atomic>
#include "zmq_lvc.h"
#include "log.h"
#include <zmq.h>
#include <stdio.h>
#include <string>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
LastValueCache::LastValueCache(int statcount,
                               const std::string *statnames,
                               std::string process_name,
                               long poll_timeout_ms) : 
  _statcount(statcount),
  _statnames(statnames),
  _process_name(process_name),
  _poll_timeout_ms(poll_timeout_ms),
  _terminate(false)
{
  TRC_DEBUG("Initializing statistics aggregator");
  _context = zmq_ctx_new();
  _subscriber = new void *[_statcount];

 
  for (int ii = 0; ii < _statcount; ii++)
  {
    std::string statname = _statnames[ii];
    void* publisher = zmq_socket(_context, ZMQ_PUB);
    zmq_bind(publisher, ("inproc://" + statname).c_str());
    _internal_publishers[statname] = publisher;
    TRC_DEBUG("Opened statistics socket inproc://%s", statname.c_str());
  }

  int rc = pthread_create(&_cache_thread,
                          NULL,
                          &last_value_cache_entry_func,
                          (void *)this);

  if (rc < 0)
  {
    TRC_ERROR("Failed to start statistics aggregator, no statistics will be available");
  }
}

LastValueCache::~LastValueCache()
{
  if (_cache_thread)
  {
    _terminate = true;
    pthread_join(_cache_thread, NULL);
  }
  delete[] _subscriber;

  for (int ii = 0; ii < _statcount; ii++)
  {
    std::string statname = _statnames[ii];
    TRC_DEBUG("Unbinding and closing statistics socket inproc://%s", statname.c_str());

    zmq_unbind(_internal_publishers[statname], ("inproc://" + statname).c_str());
    zmq_close(_internal_publishers[statname]);
  }

  zmq_ctx_destroy(_context);
}
void* LastValueCache::get_internal_publisher(std::string statname)
{
  assert(_internal_publishers.find(statname) != _internal_publishers.end());
  return _internal_publishers[statname];
}

void LastValueCache::run()
{
  zmq_pollitem_t items[_statcount + 1];

  for (int ii = 0; ii < _statcount; ii++)
  {
    _subscriber[ii] = zmq_socket(_context, ZMQ_SUB);
    TRC_DEBUG("Initializing inproc://%s statistic listener", _statnames[ii].c_str());
    zmq_connect(_subscriber[ii], ("inproc://" + _statnames[ii]).c_str());
    zmq_setsockopt(_subscriber[ii], ZMQ_SUBSCRIBE, "", 0);
  }

  _publisher = zmq_socket(_context, ZMQ_XPUB);
  int verbose = 1;
  zmq_setsockopt(_publisher, ZMQ_XPUB_VERBOSE, &verbose, sizeof(verbose));
  TRC_DEBUG("Enabled XPUB_VERBOSE mode");
  unlink((ZMQ_IPC_FOLDER_PATH + _process_name).c_str());
  zmq_bind(_publisher, ("ipc://" ZMQ_IPC_FOLDER_PATH + _process_name).c_str());
  chmod((ZMQ_IPC_FOLDER_PATH + _process_name).c_str(), 0x777);

  while (!_terminate)
  {
    // Reset the poll items
    for (int ii = 0; ii < _statcount; ii++)
    {
      items[ii].socket = _subscriber[ii];
      items[ii].fd = 0;
      items[ii].events = ZMQ_POLLIN;
      items[ii].revents = 0;
    }
    items[_statcount].socket = _publisher;
    items[_statcount].fd = 0;
    items[_statcount].events = ZMQ_POLLIN;
    items[_statcount].revents = 0;

    
    int rc = zmq_poll(items, _statcount + 1, _poll_timeout_ms);
    assert(rc >= 0 || errno == EINTR);

    for (int ii = 0; ii < _statcount; ii++)
    {
      if (items[ii].revents & ZMQ_POLLIN)
      {
        TRC_DEBUG("Update to %s statistic", _statnames[ii].c_str());
        clear_cache(_subscriber[ii]);
        while (1)
        {
          zmq_msg_t message;
          zmq_msg_t *cached_message = (zmq_msg_t *)malloc(sizeof(zmq_msg_t));
          int more;
          size_t more_size = sizeof (more);

          zmq_msg_init(&message);
          zmq_msg_init(cached_message);
          zmq_msg_recv(&message, _subscriber[ii], 0);
          zmq_msg_copy(cached_message, &message);
          _cache[_subscriber[ii]].push_back(cached_message);
          zmq_getsockopt(_subscriber[ii], ZMQ_RCVMORE, &more, &more_size);
          zmq_msg_send(&message, _publisher, more ? ZMQ_SNDMORE : 0);
          zmq_msg_close(&message);
          if (!more)
            break;      //  Last message frame
        }
      }
    }

    // Recognize incoming subscription events
    if (items[_statcount].revents & ZMQ_POLLIN)
    {
      zmq_msg_t message;
      zmq_msg_init(&message);
      zmq_msg_recv(&message, _publisher, 0);
      char *msg_body = (char *)zmq_msg_data(&message);
      if (msg_body[0] == ZMQ_NEW_SUBSCRIPTION_MARKER)
      {
        // This is a new subscription
        std::string topic = std::string(msg_body + 1, zmq_msg_size(&message) - 1);
        TRC_DEBUG("New subscription for %s", topic.c_str());
        bool recognized = false;

        for (int ii = 0; ii < _statcount; ii++)
        {
          if (topic == _statnames[ii])
          {
            TRC_DEBUG("Statistic found, check for cached value");
            recognized = true;

            // Replay the cached message if one exists
            if (_cache.find(_subscriber[ii]) != _cache.end())
            {
              replay_cache(_subscriber[ii]);
            }
            else
            {
              TRC_DEBUG("No cached record found, reporting empty statistic");
              std::string status = "OK";
              zmq_send(_publisher, _statnames[ii].c_str(), _statnames[ii].length(), ZMQ_SNDMORE);
              zmq_send(_publisher, status.c_str(), status.length(), 0);
            }
          }
        }

        if (!recognized)
        {
          TRC_DEBUG("Subscription for unknown stat %s", topic.c_str());
          std::string status = "Unknown";
          zmq_send(_publisher, topic.c_str(), topic.length(), ZMQ_SNDMORE);
          zmq_send(_publisher, status.c_str(), status.length(), 0);
        }
      }
      zmq_msg_close(&message);
    }
  }

  for (int ii = 0; ii < _statcount; ii++)
  {
    zmq_disconnect(_subscriber[ii], ("inproc://" + _statnames[ii]).c_str());
    zmq_close(_subscriber[ii]);
    clear_cache(_subscriber[ii]);
  }
  zmq_unbind(_publisher, ("ipc://" ZMQ_IPC_FOLDER_PATH + _process_name).c_str());
  unlink((ZMQ_IPC_FOLDER_PATH + _process_name).c_str());
  zmq_close(_publisher);
}

void LastValueCache::clear_cache(void *entry)
{
  TRC_DEBUG("Clearing message cache for %p", entry);
  if (_cache.find(entry) == _cache.end())
  {
    // Entry not found, add a blank vector in as we're about to fill it.
    _cache[entry] = std::vector<zmq_msg_t *>();
  }
  else
  {
    std::vector<zmq_msg_t *> *msg_list = &_cache[entry];
    std::vector<zmq_msg_t *>::iterator it = msg_list->begin();
    while (it != msg_list->end())
    {
      zmq_msg_t *cached_message = *it;
      zmq_msg_close(cached_message);
      free(cached_message);
      it = msg_list->erase(it);
    }
  }
}

void LastValueCache::replay_cache(void *entry)
{
  std::vector<zmq_msg_t *> *cache_record = &_cache[entry];
  if (cache_record->empty())
  {
    TRC_DEBUG("No cached record");
    return;
  }

  TRC_DEBUG("Replaying cache for entry %p (length: %d)", entry, cache_record->size());
  std::vector<zmq_msg_t *>::iterator it;
  for (std::vector<zmq_msg_t *>::iterator it = cache_record->begin();
       it != cache_record->end();
       it++)
  {
    zmq_msg_t message;
    zmq_msg_init(&message);
    zmq_msg_copy(&message, *it);
    zmq_sendmsg(_publisher, &message, (it + 1 != cache_record->end()) ? ZMQ_SNDMORE : 0);
    zmq_msg_close(&message);
  }
}

void* LastValueCache::last_value_cache_entry_func(void *lvc)
{
  ((LastValueCache *)lvc)->run();
  return NULL;
}

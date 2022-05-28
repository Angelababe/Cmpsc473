#include <atomic>
#include "realmmanager.h"
#include "utils.h"
#include "cpp_common_pd_definitions.h"

#include <boost/algorithm/string/replace.hpp>

RealmManager::RealmManager(Diameter::Stack* stack,
                           std::string realm,
                           std::string host,
                           int max_peers,
                           DiameterResolver* resolver) :
                           _stack(stack),
                           _realm(realm),
                           _host(host),
                           _max_peers(max_peers),
                           _resolver(resolver),
                           _terminating(false)
{
  pthread_mutex_init(&_main_thread_lock, NULL);
  pthread_condattr_t cond_attr;
  pthread_condattr_init(&cond_attr);
  pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
  pthread_cond_init(&_cond, &cond_attr);
  pthread_condattr_destroy(&cond_attr);

  pthread_rwlock_init(&_peers_lock, NULL);
}

void RealmManager::start()
{
  using namespace std::placeholders;

  pthread_create(&_thread, NULL, thread_function, this);
  _stack->register_peer_hook_hdlr("realmmanager",
                                  std::bind(&RealmManager::peer_connection_cb,
                                            this,
                                            _1,
                                            _2,
                                            _3));
  _stack->register_rt_out_cb("realmmanager",
                             std::bind(&RealmManager::srv_priority_cb,
                                       this,
                                       _1));
}

RealmManager::~RealmManager()
{
  pthread_mutex_destroy(&_main_thread_lock);
  pthread_cond_destroy(&_cond);

  pthread_rwlock_destroy(&_peers_lock);
}

void RealmManager::stop()
{
  pthread_mutex_lock(&_main_thread_lock);
  _terminating = true;
  pthread_cond_signal(&_cond);
  pthread_mutex_unlock(&_main_thread_lock);
  pthread_join(_thread, NULL);
  _stack->unregister_peer_hook_hdlr("realmmanager");
  _stack->unregister_rt_out_cb("realmmanager");
}

void RealmManager::peer_connection_cb(bool connection_success,
                                      const std::string& host,
                                      const std::string& realm)
{
  pthread_mutex_lock(&_main_thread_lock);
  pthread_rwlock_rdlock(&_peers_lock);

  std::map<std::string, Diameter::Peer*>::iterator ii = _peers.find(host);
  if (ii != _peers.end())
  {
    Diameter::Peer* peer = ii->second;
    if (connection_success)
    {
      if (peer->realm().empty() || (peer->realm().compare(realm) == 0))
      {
        TRC_INFO("Successfully connected to %s in realm %s",
                 host.c_str(),
                 realm.c_str());
        pthread_rwlock_unlock(&_peers_lock);
        pthread_rwlock_wrlock(&_peers_lock);
        peer->set_connected();
      }
      else
      {
        TRC_ERROR("Connected to %s in wrong realm (expected %s, got %s), disconnect",
                  host.c_str(),
                  peer->realm().c_str(),
                  realm.c_str());
        _stack->remove(peer);
        _resolver->blacklist(peer->addr_info());
        pthread_rwlock_unlock(&_peers_lock);
        pthread_rwlock_wrlock(&_peers_lock);
        delete peer;
        _peers.erase(ii);

        pthread_cond_signal(&_cond);
      }
    }
    else
    {
      TRC_ERROR("Failed to connect to %s", host.c_str());
      _resolver->blacklist(peer->addr_info());
      pthread_rwlock_unlock(&_peers_lock);
      pthread_rwlock_wrlock(&_peers_lock);
      delete peer;
      _peers.erase(ii);

      pthread_cond_signal(&_cond);
    }
  }
  else
  {
    TRC_ERROR("Unexpected host on peer connection callback from freeDiameter: %s",
              host.c_str());
  }

  pthread_rwlock_unlock(&_peers_lock);
  pthread_mutex_unlock(&_main_thread_lock);
  return;
}

void RealmManager::srv_priority_cb(struct fd_list* candidates)
{
  pthread_rwlock_rdlock(&_peers_lock);

  for (struct fd_list* li = candidates->next; li != candidates; li = li->next)
  {
    struct rtd_candidate* candidate = (struct rtd_candidate*)li;
    std::map<std::string, Diameter::Peer*>::iterator ii =
                                             _peers.find(candidate->cfg_diamid);
    if (ii != _peers.end())
    {
      if (candidate->score > 0)
      {
        int new_score = candidate->score - (ii->second)->addr_info().priority;

        new_score = std::max(new_score, 1);
        TRC_DEBUG("freeDiameter routing score for candidate %.*s is changing from %d to %d",
                  candidate->cfg_diamidlen,
                  candidate->cfg_diamid,
                  candidate->score,
                  new_score);
        candidate->score = new_score;
      }
      else
      {
        TRC_DEBUG("freeDiameter routing score for candidate %.*s is negative (%d) - not changing",
                  candidate->cfg_diamidlen,
                  candidate->cfg_diamid,
                  candidate->score);
      }
    }
    else
    {
      TRC_WARNING("Unexpected candidate peer %s for Diameter message routing",
                  candidate->cfg_diamid);
    }
  }

  pthread_rwlock_unlock(&_peers_lock);
  return;
}

void* RealmManager::thread_function(void* realm_manager_ptr)
{
  ((RealmManager*)realm_manager_ptr)->thread_function();
  return NULL;
}
void RealmManager::thread_function()
{
  int ttl = 0;
  struct timespec ts;

  pthread_mutex_lock(&_main_thread_lock);

  do
  {
    manage_connections(ttl);

    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += ttl;
    pthread_cond_timedwait(&_cond, &_main_thread_lock, &ts);

  } while (!_terminating);

  for (std::map<std::string, Diameter::Peer*>::iterator ii = _peers.begin();
       ii != _peers.end();
       ii++)
  {
    _stack->remove(ii->second);
    delete (ii->second);
  }

  _peers.clear();

  pthread_mutex_unlock(&_main_thread_lock);
}
void RealmManager::manage_connections(int& ttl)
{
  std::vector<AddrInfo> targets;
  std::vector<std::string> new_peers;
  std::vector<Diameter::Peer*> connected_peers;
  bool ret;

  pthread_rwlock_rdlock(&_peers_lock);
  std::map<std::string, Diameter::Peer*> locked_peers = _peers;
  pthread_rwlock_unlock(&_peers_lock);

  // 1.
  _resolver->resolve(_realm, _host, _max_peers, targets, ttl);

  ttl = std::max(5, ttl);
  ttl = std::min(300, ttl);

  // 2.
  for (std::vector<AddrInfo>::iterator ii = targets.begin();
       ii != targets.end();
       ii++)
  {
    new_peers.push_back(Utils::ip_addr_to_arpa((*ii).address));
  }

  // 3.
  for (std::map<std::string, Diameter::Peer*>::iterator ii = locked_peers.begin();
       ii != locked_peers.end();
       ii++)
  {
    if ((ii->second)->connected())
    {
      connected_peers.push_back(ii->second);
    }
  }

  // 4.
  for (std::vector<Diameter::Peer*>::iterator ii = connected_peers.begin();
       (ii != connected_peers.end()) &&
       (((int)connected_peers.size() > _max_peers) ||
        ((int)new_peers.size() < _max_peers));
      )
  {
    if (std::find(new_peers.begin(),
                  new_peers.end(),
                  (*ii)->host()) == new_peers.end())
    {
      Diameter::Peer* peer = *ii;
      TRC_STATUS("Removing peer: %s", peer->host().c_str());
      ii = connected_peers.erase(ii);
      std::map<std::string, Diameter::Peer*>::iterator jj =
                                                locked_peers.find(peer->host());

      if (jj != locked_peers.end())
      {
        locked_peers.erase(jj);
      }
      _stack->remove(peer);
      delete peer;
    }
    else
    {
      ii++;
    }
  }

  // 5.
  int zombies = 0;
  for (std::vector<AddrInfo>::iterator ii = targets.begin();
       ii != targets.end();
       ii++)
  {
    std::string hostname = Utils::ip_addr_to_arpa((*ii).address);

    // Check whether this new target is already in our list of peers, and if it
    // isn't, add it.
    std::map<std::string, Diameter::Peer*>::iterator jj =
                                                    locked_peers.find(hostname);
    if (jj == locked_peers.end())
    {
      Diameter::Peer* peer = new Diameter::Peer(*ii, hostname, _realm, 0);
      TRC_STATUS("Adding peer: %s", hostname.c_str());
      ret = _stack->add(peer);
      if (ret)
      {
        locked_peers[hostname] = peer;
      }
      else
      {
        TRC_STATUS("Peer already exists: %s", hostname.c_str());
        delete peer;

        zombies++;
      }
    }
    else
    {
      jj->second->set_srv_priority(ii->priority);
    }
  }

  _stack->peer_count(locked_peers.size() + zombies, connected_peers.size());

  // 7. Update the stored _peers map.
  pthread_rwlock_wrlock(&_peers_lock);
  _peers = locked_peers;
  pthread_rwlock_unlock(&_peers_lock);
}

#include <atomic>
#include <time.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "log.h"
#include "utils.h"
#include "baseresolver.h"
#include "sas.h"
#include "sasevent.h"
#include "weightedselector.h"

void PrintTo(const AddrInfo& ai, std::ostream* os)
{
  *os << ai.to_string();
}

void BaseResolver::add_target_to_log_string(std::string& log_string,
                                            const AddrInfo& addr,
                                            const std::string& state)
{
  if (!log_string.empty())
  {
    log_string += ", ";
  }

  log_string += addr.address_and_port_to_string() + " (" + state + ")";
}

BaseResolver::BaseResolver(DnsCachedResolver* dns_client) :
  _naptr_factory(),
  _naptr_cache(),
  _srv_factory(),
  _srv_cache(),
  _hosts(),
  _dns_client(dns_client)
{
}

BaseResolver::~BaseResolver()
{
}
void BaseResolver::clear_blacklist()
{
  TRC_DEBUG("Clear blacklist");
  pthread_mutex_lock(&_hosts_lock);
  _hosts.clear();
  pthread_mutex_unlock(&_hosts_lock);
}

void BaseResolver::create_naptr_cache(const std::map<std::string, int> naptr_services)
{
  TRC_DEBUG("Create NAPTR cache");
  _naptr_factory = new NAPTRCacheFactory(naptr_services, DEFAULT_TTL, _dns_client);
  _naptr_cache = new NAPTRCache(_naptr_factory);
}
void BaseResolver::create_srv_cache()
{
  TRC_DEBUG("Create SRV cache");
  _srv_factory = new SRVCacheFactory(DEFAULT_TTL, _dns_client);
  _srv_cache = new SRVCache(_srv_factory);
}
void BaseResolver::create_blacklist(int blacklist_duration, int graylist_duration)
{
  TRC_DEBUG("Create black list");
  pthread_mutex_init(&_hosts_lock, NULL);
  _default_blacklist_duration = blacklist_duration;
  _default_graylist_duration = graylist_duration;
}

void BaseResolver::destroy_naptr_cache()
{
  TRC_DEBUG("Destroy NAPTR cache");
  delete _naptr_cache;
  delete _naptr_factory;
}

void BaseResolver::destroy_srv_cache()
{
  TRC_DEBUG("Destroy SRV cache");
  delete _srv_cache;
  delete _srv_factory;
}

void BaseResolver::destroy_blacklist()
{
  TRC_DEBUG("Destroy blacklist");
  _default_blacklist_duration = 0;
  _default_graylist_duration = 0;
  pthread_mutex_destroy(&_hosts_lock);
}
void BaseResolver::srv_resolve(const std::string& srv_name,
                               int af,
                               int transport,
                               int retries,
                               std::vector<AddrInfo>& targets,
                               int& ttl,
                               SAS::TrailId trail,
                               int allowed_host_state)
{
  LazySRVResolveIter* targets_iter = (LazySRVResolveIter*) srv_resolve_iter(srv_name, af, transport, trail, allowed_host_state);
  targets = targets_iter->take(retries);
  ttl = targets_iter->get_min_ttl();
  delete targets_iter; targets_iter = nullptr;
}

BaseAddrIterator* BaseResolver::srv_resolve_iter(const std::string& srv_name,
                                                 int af,
                                                 int transport,
                                                 SAS::TrailId trail,
                                                 int allowed_host_state)
{
  TRC_DEBUG("Creating a lazy iterator for SRV Resolution");
  return new LazySRVResolveIter(this,
                                af,
                                transport,
                                srv_name,
                                trail,
                                allowed_host_state);
}
void BaseResolver::a_resolve(const std::string& hostname,
                             int af,
                             int port,
                             int transport,
                             int retries,
                             std::vector<AddrInfo>& targets,
                             int& ttl,
                             SAS::TrailId trail,
                             int allowed_host_state)
{
  BaseAddrIterator* it = a_resolve_iter(hostname, af, port, transport, ttl, trail, allowed_host_state);
  targets = it->take(retries);
  delete it; it = nullptr;
}

BaseAddrIterator* BaseResolver::a_resolve_iter(const std::string& hostname,
                                               int af,
                                               int port,
                                               int transport,
                                               int& ttl,
                                               SAS::TrailId trail,
                                               int allowed_host_state)
{
  DnsResult result = _dns_client->dns_query(hostname, (af == AF_INET) ? ns_t_a : ns_t_aaaa, trail);
  ttl = result.ttl();

  TRC_DEBUG("Found %ld A/AAAA records, creating iterator", result.records().size());

  return new LazyAResolveIter(result, this, port, transport, trail, allowed_host_state);
}
IP46Address BaseResolver::to_ip46(const DnsRRecord* rr)
{
  IP46Address addr;
  if (rr->rrtype() == ns_t_a)
  {
    DnsARecord* ar = (DnsARecord*)rr;
    addr.af = AF_INET;
    addr.addr.ipv4 = ar->address();
  }
  else
  {
    DnsAAAARecord* ar = (DnsAAAARecord*)rr;
    addr.af = AF_INET6;
    addr.addr.ipv6 = ar->address();
  }

  return addr;
}
void BaseResolver::blacklist(const AddrInfo& ai,
                             int blacklist_ttl,
                             int graylist_ttl)
{
  std::string ai_str = ai.to_string();
  TRC_DEBUG("Add %s to blacklist for %d seconds, graylist for %d seconds",
            ai_str.c_str(), blacklist_ttl, graylist_ttl);
  pthread_mutex_lock(&_hosts_lock);
  _hosts.erase(ai);
  _hosts.emplace(ai, Host(blacklist_ttl, graylist_ttl));
  pthread_mutex_unlock(&_hosts_lock);
}

BaseResolver::NAPTRCacheFactory::NAPTRCacheFactory(const std::map<std::string, int>& services,
                                                   int default_ttl,
                                                   DnsCachedResolver* dns_client) :
  _services(services),
  _default_ttl(default_ttl),
  _dns_client(dns_client)
{
}

BaseResolver::NAPTRCacheFactory::~NAPTRCacheFactory()
{
}

std::shared_ptr<BaseResolver::NAPTRReplacement> BaseResolver::NAPTRCacheFactory::get(std::string key,
                                                                                     int& ttl,
                                                                                     SAS::TrailId trail)
{
  TRC_DEBUG("NAPTR cache factory called for %s", key.c_str());
  std::shared_ptr<NAPTRReplacement> repl = nullptr;
  std::string query_key = key;
  int expires = 0;
  bool loop_again = true;

  while (loop_again)
  {
    loop_again = false;
    TRC_DEBUG("Sending DNS NAPTR query for %s", query_key.c_str());
    DnsResult result = _dns_client->dns_query(query_key, ns_t_naptr, trail);

    if (!result.records().empty())
    {
      std::vector<DnsNaptrRecord*> filtered;

      for (std::vector<DnsRRecord*>::const_iterator i = result.records().begin();
           i != result.records().end();
           ++i)
      {
        DnsNaptrRecord* naptr = (DnsNaptrRecord*)(*i);
        if ((_services.find(naptr->service()) != _services.end()) &&
            ((strcasecmp(naptr->flags().c_str(), "S") == 0) ||
             (strcasecmp(naptr->flags().c_str(), "A") == 0) ||
             (strcasecmp(naptr->flags().c_str(), "") == 0)))
        {
          filtered.push_back(naptr);
        }
      }
      std::sort(filtered.begin(),
                filtered.end(),
                BaseResolver::NAPTRCacheFactory::compare_naptr_order_preference);
      for (size_t ii = 0; ii < filtered.size(); ++ii)
      {
        DnsNaptrRecord* naptr = filtered[ii];
        std::string replacement = naptr->replacement();

        if ((replacement == "") &&
            (naptr->regexp() != ""))
        {
          boost::regex regex;
          std::string replace;
          if (parse_regex_replace(naptr->regexp(), regex, replace))
          {
            replacement = boost::regex_replace(key,
                                               regex,
                                               replace,
                                               boost::regex_constants::format_first_only);
          }
        }
        if ((expires == 0) ||
            (expires > naptr->expires()))
        {
          expires = naptr->expires();
        }

        if (replacement != "")
        {
          if (strcasecmp(naptr->flags().c_str(), "") == 0)
          {
            query_key = replacement;
            loop_again = true;
          }
          else
          {
            repl = std::make_shared<NAPTRReplacement>();
            repl->replacement = replacement;
            repl->flags = naptr->flags();
            repl->transport = _services[naptr->service()];
            ttl = expires - time(NULL);
          }
          break;
        }
      }
    }
    else
    {
      ttl = _default_ttl;
    }
  }
  return repl;
}

bool BaseResolver::NAPTRCacheFactory::parse_regex_replace(const std::string& regex_replace,
                                                          boost::regex& regex,
                                                          std::string& replace)
{
  bool success = false;
  std::vector<std::string> match_replace;
  Utils::split_string(regex_replace, regex_replace[0], match_replace);

  if (match_replace.size() == 2)
  {
    TRC_DEBUG("Split regex into match=%s, replace=%s", match_replace[0].c_str(), match_replace[1].c_str());
    try
    {
      regex.assign(match_replace[0]);
      replace = match_replace[1];
      success = true;
    }
    catch (...)
    {
      success = false;
    }
  }
  else
  {
    success = false;
  }

  return success;
}


bool BaseResolver::NAPTRCacheFactory::compare_naptr_order_preference(DnsNaptrRecord* r1,
                                                                     DnsNaptrRecord* r2)
{
  return ((r1->order() < r2->order()) ||
          ((r1->order() == r2->order()) &&
           (r1->preference() < r2->preference())));
}


BaseResolver::SRVCacheFactory::SRVCacheFactory(int default_ttl,
                                               DnsCachedResolver* dns_client) :
  _default_ttl(default_ttl),
  _dns_client(dns_client)
{
}

BaseResolver::SRVCacheFactory::~SRVCacheFactory()
{
}

std::shared_ptr<BaseResolver::SRVPriorityList> BaseResolver::SRVCacheFactory::get(std::string key,
                                                                                  int& ttl,
                                                                                  SAS::TrailId trail)
{
  TRC_DEBUG("SRV cache factory called for %s", key.c_str());
  std::shared_ptr<BaseResolver::SRVPriorityList> srv_list = nullptr;

  DnsResult result = _dns_client->dns_query(key, ns_t_srv, trail);

  if (!result.records().empty())
  {
    TRC_DEBUG("SRV query returned %d records", result.records().size());
    srv_list = std::make_shared<BaseResolver::SRVPriorityList>();
    ttl = result.ttl();

    std::sort(result.records().begin(), result.records().end(), compare_srv_priority);
    for (std::vector<DnsRRecord*>::const_iterator i = result.records().begin();
         i != result.records().end();
         ++i)
    {
      DnsSrvRecord* srv_record = (DnsSrvRecord*)(*i);
      std::vector<SRV>& plist = (*srv_list)[srv_record->priority()];
      plist.push_back(SRV());
      SRV& srv = plist.back();
      srv.target = srv_record->target();
      srv.port = srv_record->port();
      srv.priority = srv_record->priority();
      srv.weight = srv_record->weight();
      srv.weight = (srv.weight == 0) ? 1 : srv.weight * 100;
    }
  }
  else
  {
    ttl = _default_ttl;
  }

  return srv_list;
}

bool BaseResolver::SRVCacheFactory::compare_srv_priority(DnsRRecord* r1,
                                                         DnsRRecord* r2)
{
  return (((DnsSrvRecord*)r1)->priority() < ((DnsSrvRecord*)r2)->priority());
}

BaseResolver::Host::Host(int blacklist_ttl, int graylist_ttl) :
  _being_probed(false)
{
  time_t current_time = time(NULL);
  _blacklist_expiry_time = current_time + blacklist_ttl;
  _graylist_expiry_time = current_time + blacklist_ttl + graylist_ttl;
}

BaseResolver::Host::~Host()
{
}

std::string BaseResolver::Host::state_to_string(State state)
{
  switch(state)
  {
  case State::WHITE:
    return "WHITE";
  case State::GRAY_NOT_PROBING:
    return "GRAY_NOT_PROBING";
  case State::GRAY_PROBING:
    return "GRAY_PROBING";
  case State::BLACK:
    return "BLACK";
    // LCOV_EXCL_START
  default:
    return "UNKNOWN";
    // LCOV_EXCL_STOP
  }
}

BaseResolver::Host::State BaseResolver::Host::get_state(time_t current_time)
{
  if (current_time < _blacklist_expiry_time)
  {
    return State::BLACK;
  }
  else if (current_time < _graylist_expiry_time)
  {
    if (_being_probed)
    {
      return State::GRAY_PROBING;
    }
    else
    {
      return State::GRAY_NOT_PROBING;
    }
  }
  else
  {
    return State::WHITE;
  }
}

void BaseResolver::Host::success()
{
  if (get_state() != State::BLACK)
  {
    _being_probed = false;
    _blacklist_expiry_time = 0;
    _graylist_expiry_time = 0;
  }
}

void BaseResolver::Host::selected_for_probing(pthread_t user_id)
{
  if (get_state() == State::GRAY_NOT_PROBING)
  {
    _being_probed = true;
    _probing_user_id = user_id;
  }
}

BaseResolver::Host::State BaseResolver::host_state(const AddrInfo& ai,
                                                   time_t current_time)
{
  Host::State state;
  Hosts::iterator i = _hosts.find(ai);
  std::string ai_str;

  if (Log::enabled(Log::DEBUG_LEVEL))
  {
    ai_str = ai.to_string();
  }

  if (i != _hosts.end())
  {
    state = i->second.get_state(current_time);
    if (state == Host::State::WHITE)
    {
      TRC_DEBUG("%s graylist time elapsed", ai_str.c_str());
      _hosts.erase(i);
    }
  }
  else
  {
    state = Host::State::WHITE;
  }

  if (Log::enabled(Log::DEBUG_LEVEL))
  {
    std::string state_str = Host::state_to_string(state);
    TRC_DEBUG("%s has state: %s", ai_str.c_str(), state_str.c_str());
  }

  return state;
}

bool BaseResolver::select_address(const AddrInfo& addr,
                                  SAS::TrailId trail,
                                  int allowed_host_state)
{
  bool allowed;
  const bool whitelisted_allowed = allowed_host_state & BaseResolver::WHITELISTED;
  const bool blacklisted_allowed = allowed_host_state & BaseResolver::BLACKLISTED;

  pthread_mutex_lock(&_hosts_lock);

  BaseResolver::Host::State state = host_state(addr);

  switch (state)
  {
  case BaseResolver::Host::State::WHITE:
    allowed = whitelisted_allowed;
    break;

  case BaseResolver::Host::State::GRAY_NOT_PROBING:
    allowed = whitelisted_allowed;
    if (allowed)
    {
      select_for_probing(addr);
    }
    break;

  case BaseResolver::Host::State::GRAY_PROBING:
    allowed = blacklisted_allowed;
    break;

  case BaseResolver::Host::State::BLACK:
    allowed = blacklisted_allowed;
    break;

  default:
    TRC_WARNING("Unknown host state %d", (int)state);
    allowed = false;
    break;
  }

  pthread_mutex_unlock(&_hosts_lock);

  std::string host_state_str = BaseResolver::Host::state_to_string(state);
  std::string addr_str = addr.address_and_port_to_string();

  TRC_DEBUG("Address %s is in state %s and %s allowed to be used based on an "
            "allowed host state bitfield of 0x%x",
            addr_str.c_str(),
            host_state_str.c_str(),
            allowed ? "is" : "is not",
            allowed_host_state);

  if (allowed)
  {
    SAS::Event event(trail, SASEvent::BASERESOLVE_IP_ALLOWED, 0);
    event.add_var_param(addr_str);
  }
  else
  {
    SAS::Event event(trail, SASEvent::BASERESOLVE_IP_NOT_ALLOWED, 0);
    event.add_static_param(whitelisted_allowed);
    event.add_static_param(blacklisted_allowed);
    event.add_var_param(addr_str);
    event.add_var_param(host_state_str);
  }

  return allowed;
}

void BaseResolver::success(const AddrInfo& ai)
{
  if (Log::enabled(Log::DEBUG_LEVEL))
  {
    std::string ai_str = ai.to_string();
    TRC_DEBUG("Successful response from  %s", ai_str.c_str());
  }

  pthread_mutex_lock(&_hosts_lock);

  Hosts::iterator i = _hosts.find(ai);

  if (i != _hosts.end())
  {
    i->second.success();
  }

  pthread_mutex_unlock(&_hosts_lock);
}

void BaseResolver::select_for_probing(const AddrInfo& ai)
{
  Hosts::iterator i = _hosts.find(ai);

  if (i != _hosts.end())
  {
    std::string ai_str = ai.to_string();
    TRC_DEBUG("%s selected for probing", ai_str.c_str());
    i->second.selected_for_probing(pthread_self());
  }
}
void BaseResolver::no_targets_resolved_logging(const std::string name,
                                               SAS::TrailId trail,
                                               bool whitelisted_allowed,
                                               bool blacklisted_allowed)
{
  if (whitelisted_allowed != blacklisted_allowed)
  {
    SAS::Event event(trail, SASEvent::BASERESOLVE_NO_ALLOWED_RECORDS, 0);
    event.add_var_param(name);
    event.add_static_param(blacklisted_allowed);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(trail, SASEvent::BASERESOLVE_NO_RECORDS, 0);
    event.add_var_param(name);
    SAS::report_event(event);
  }
}

void BaseResolver::dns_query(std::vector<std::string>& domains,
                             int dnstype,
                             std::vector<DnsResult>& results,
                             SAS::TrailId trail)
{
  _dns_client->dns_query(domains, dnstype, results, trail);
}

std::shared_ptr<BaseResolver::SRVPriorityList> BaseResolver::get_srv_list(const std::string& srv_name,
                                                                          int &ttl,
                                                                          SAS::TrailId trail)
{
  return _srv_cache->get(srv_name, ttl, trail);
}

bool BaseAddrIterator::next(AddrInfo &target)
{
  bool value_set;
  std::vector<AddrInfo> next_one = take(1);

  if (!next_one.empty())
  {
    target = next_one.front();
    value_set = true;
  }
  else
  {
    value_set = false;
  }

  return value_set;
}

std::vector<AddrInfo> SimpleAddrIterator::take(int num_requested_targets)
{
  int num_targets_to_return = std::min(num_requested_targets, int(_targets.size()));
  std::vector<AddrInfo>::iterator targets_it = _targets.begin();
  std::advance(targets_it, num_targets_to_return);
  std::vector<AddrInfo> targets(_targets.begin(), targets_it);
  _targets = std::vector<AddrInfo>(targets_it, _targets.end());

  return targets;
}

LazyAResolveIter::LazyAResolveIter(DnsResult& dns_result,
                                   BaseResolver* resolver,
                                   int port,
                                   int transport,
                                   SAS::TrailId trail,
                                   int allowed_host_state) :
  _resolver(resolver),
  _allowed_host_state(allowed_host_state),
  _trail(trail),
  _first_call(true)
{
  _hostname = dns_result.domain();

  AddrInfo ai;
  ai.port = port;
  ai.transport = transport;
  _unused_results.reserve(dns_result.records().size());
  for (std::vector<DnsRRecord*>::const_iterator result_it = dns_result.records().begin();
       result_it != dns_result.records().end();
       ++result_it)
  {
    ai.address = _resolver->to_ip46(*result_it);
    _unused_results.push_back(ai);
  }
  std::random_shuffle(_unused_results.begin(), _unused_results.end());
}

std::vector<AddrInfo> LazyAResolveIter::take(int num_requested_targets)
{
  TRC_DEBUG("Attempting to get %d targets for host:%s. allowed_host_state = %d",
            num_requested_targets,
            _hostname.c_str(),
            _allowed_host_state);
  const bool whitelisted_allowed = _allowed_host_state & BaseResolver::WHITELISTED;
  const bool blacklisted_allowed = _allowed_host_state & BaseResolver::BLACKLISTED;
  std::vector<AddrInfo> targets;
  std::string targets_log_str;
  pthread_mutex_lock(&(_resolver->_hosts_lock));
  if (_first_call && whitelisted_allowed)
  {
    for (std::vector<AddrInfo>::reverse_iterator result_it = _unused_results.rbegin();
         result_it != _unused_results.rend();
         ++result_it)
    {
      if (_resolver->host_state(*result_it) == BaseResolver::Host::State::GRAY_NOT_PROBING)
      {
        _resolver->select_for_probing(*result_it);
        targets.push_back(*result_it);

        BaseResolver::add_target_to_log_string(targets_log_str, *result_it, "graylisted");
        TRC_DEBUG("Added a graylisted server to targets, now have %ld of %d",
                  targets.size(),
                  num_requested_targets);
        _unused_results.erase(std::next(result_it).base());
        break;
      }
    }
  }
  while ((_unused_results.size() > 0) &&
         (targets.size() < (size_t)num_requested_targets))
  {
    AddrInfo result = _unused_results.back();
    _unused_results.pop_back();
    std::string target = result.address_and_port_to_string() + ";";

    if (_resolver->host_state(result) == BaseResolver::Host::State::WHITE)
    {
      if (whitelisted_allowed)
      {
        targets.push_back(result);

        BaseResolver::add_target_to_log_string(targets_log_str, result, "whitelisted");
        TRC_DEBUG("Added a whitelisted server to targets, now have %ld of %d",
                  targets.size(),
                  num_requested_targets);
      }
    }
    else
    {

      if (blacklisted_allowed)
      {
        if (whitelisted_allowed)
        {
          _unhealthy_results.push_back(result);

          TRC_DEBUG("Found an unhealthy server, now have %ld unhealthy results",
                    _unhealthy_results.size());
        }
        else
        {
          targets.push_back(result);
          TRC_DEBUG("Added a blacklisted or graylisted server to targets, now have %ld of %d",
                    targets.size(),
                    num_requested_targets);
        }
      }
    }
  }

  pthread_mutex_unlock(&(_resolver->_hosts_lock));

  while ((_unhealthy_results.size() > 0) && (targets.size() < (size_t)num_requested_targets))
  {
    AddrInfo result = _unhealthy_results.back();
    _unhealthy_results.pop_back();

    targets.push_back(result);

    BaseResolver::add_target_to_log_string(targets_log_str, result, "unhealthy");
    TRC_DEBUG("Added an unhealthy server to targets, now have %ld of %d",
              targets.size(),
              num_requested_targets);
  }

  if (_trail != 0)
  {
    SAS::Event event(_trail, SASEvent::BASERESOLVE_A_RESULT_TARGET_SELECT, 0);
    event.add_static_param(whitelisted_allowed);
    event.add_static_param(blacklisted_allowed);
    event.add_var_param(_hostname);
    event.add_var_param(targets_log_str);
    SAS::report_event(event);

    if (targets.empty() && _first_call)
    {
      _resolver->no_targets_resolved_logging(_hostname,
                                             _trail,
                                             whitelisted_allowed,
                                             blacklisted_allowed);
    }
  }

  _first_call = false;

  return targets;
}

LazySRVResolveIter::LazySRVResolveIter(BaseResolver* resolver,
                                       int af,
                                       int transport,
                                       const std::string& srv_name,
                                       SAS::TrailId trail,
                                       int allowed_host_state) :
  _resolver(resolver),
  _af(af),
  _transport(transport),
  _srv_name(srv_name),
  _ttl(0),
  _trail(trail),
  _search_for_gray(true),
  _unprobed_gray_target(),
  _gray_found(false),
  _whitelisted_addresses_by_srv(),
  _unhealthy_addresses_by_srv(),
  _unhealthy_targets(),
  _current_srv(0),
  _unhealthy_target_pos(0)
{
  _whitelisted_allowed = allowed_host_state & BaseResolver::WHITELISTED;
  _blacklisted_allowed = allowed_host_state & BaseResolver::BLACKLISTED;
  _srv_list = _resolver->get_srv_list(srv_name, _ttl, trail);

  if (_srv_list != nullptr)
  {
    TRC_DEBUG("Found SRV records at %ld priority levels", _srv_list->size());

    _next_priority_level = _srv_list->begin();
  }
  else
  {
    TRC_DEBUG("No SRV records found");
  }
}

std::vector<AddrInfo> LazySRVResolveIter::take(int num_requested_targets)
{
  std::vector<AddrInfo> targets;

  targets.reserve(num_requested_targets);
  bool add_unhealthy = false;
  std::string targets_log_str;
  int num_targets_to_find = num_requested_targets;
  if (_srv_list != nullptr)
  {
    while (num_targets_to_find > 0)
    {
      if (priority_level_complete())
      {
        if (!prepare_priority_level())
        {
          add_unhealthy = _whitelisted_allowed && _blacklisted_allowed;
          break;
        }
      }
      num_targets_to_find = get_from_priority_level(targets,
                                                    num_targets_to_find,
                                                    num_requested_targets,
                                                    targets_log_str);
    }

    if (add_unhealthy)
    {
      size_t to_copy = std::min((size_t) num_targets_to_find, _unhealthy_targets.size() - _unhealthy_target_pos);
      TRC_VERBOSE("Adding %ld unhealthy servers", to_copy);

      for (size_t ii = 0; ii < to_copy; ++ii)
      {
        targets.push_back(_unhealthy_targets[_unhealthy_target_pos]);

        BaseResolver::add_target_to_log_string(targets_log_str,
                                               _unhealthy_targets[_unhealthy_target_pos],
                                               "unhealthy");
        TRC_DEBUG("Added an unhealthy server to targets, now have %ld of %d",
                  targets.size(),
                  num_requested_targets);

        --num_targets_to_find;
        ++_unhealthy_target_pos;
      }
    }

    if (num_targets_to_find > 0)
    {
      TRC_DEBUG("Not enough addresses found of the desired host state. Returning %d out of %ld total requested", targets.size(), num_requested_targets);
    }
  }

  if (_trail != 0)
  {
    SAS::Event event(_trail, SASEvent::BASERESOLVE_SRV_RESULT, 0);
    event.add_static_param(_whitelisted_allowed);
    event.add_static_param(_blacklisted_allowed);
    event.add_var_param(_srv_name);
    event.add_var_param(targets_log_str);
    SAS::report_event(event);

    if (targets.empty())
    {
      _resolver->no_targets_resolved_logging(_srv_name, _trail, _whitelisted_allowed, _blacklisted_allowed);
    }
  }

  return targets;
}

int LazySRVResolveIter::get_min_ttl()
{
  return _ttl;
}

bool LazySRVResolveIter::prepare_priority_level()
{
  if (_next_priority_level != _srv_list->end())
  {
    TRC_VERBOSE("Processing %d SRVs with priority %d", _next_priority_level->second.size(), _next_priority_level->first);

    _whitelisted_addresses_by_srv.clear();
    _unhealthy_addresses_by_srv.clear();
    _current_srv = 0;
    std::vector<const BaseResolver::SRV*> srvs;
    srvs.reserve(_next_priority_level->second.size());
    WeightedSelector<BaseResolver::SRV> selector(_next_priority_level->second);
    while (selector.total_weight() > 0)
    {
      int ii = selector.select();
      TRC_DEBUG("Selected SRV %s:%d, weight = %d",
                _next_priority_level->second[ii].target.c_str(),
                _next_priority_level->second[ii].port,
                _next_priority_level->second[ii].weight);
      srvs.push_back(&_next_priority_level->second[ii]);
    }
    std::vector<std::string> a_targets;
    std::vector<DnsResult> a_results;
    a_targets.reserve(srvs.size());
    a_results.reserve(srvs.size());

    for (size_t ii = 0; ii < srvs.size(); ++ii)
    {
      a_targets.push_back(srvs[ii]->target);
    }

    TRC_VERBOSE("Do A record look-ups for %ld SRVs", a_targets.size());
    _resolver->dns_query(a_targets,
                         (_af == AF_INET) ? ns_t_a : ns_t_aaaa,
                         a_results,
                         _trail);
    _whitelisted_addresses_by_srv.resize(srvs.size());
    _unhealthy_addresses_by_srv.resize(srvs.size());

    for (size_t ii = 0; ii < srvs.size(); ++ii)
    {
      DnsResult& a_result = a_results[ii];
      TRC_DEBUG("SRV %s:%d returned %ld IP addresses",
                srvs[ii]->target.c_str(),
                srvs[ii]->port,
                a_result.records().size());
      std::vector<AddrInfo> &whitelisted_addresses = _whitelisted_addresses_by_srv[ii];
      std::vector<AddrInfo> &unhealthy_addresses = _unhealthy_addresses_by_srv[ii];

      pthread_mutex_lock(&(_resolver->_hosts_lock));
      AddrInfo ai;
      ai.transport = _transport;
      ai.port = srvs[ii]->port;
      ai.weight = srvs[ii]->weight;
      ai.priority = srvs[ii]->priority;

      for (size_t jj = 0; jj < a_result.records().size(); ++jj)
      {
        ai.address = _resolver->to_ip46(a_result.records()[jj]);

        BaseResolver::Host::State addr_state = _resolver->host_state(ai);
        std::string target = "[" + ai.address_and_port_to_string() + "] ";

        if ((addr_state == BaseResolver::Host::State::GRAY_NOT_PROBING) &&
            _search_for_gray &&
            _whitelisted_allowed)
        {
          _search_for_gray = false;

          _gray_found = true;

          _unprobed_gray_target = ai;
        }
        else if (addr_state == BaseResolver::Host::State::WHITE)
        {
          if (_whitelisted_allowed)
          {
            whitelisted_addresses.push_back(ai);
          }
        }
        else
        {
          if (_blacklisted_allowed)
          {
            unhealthy_addresses.push_back(ai);
          }
        }
        _ttl = std::min(_ttl, a_result.ttl());
      }

      pthread_mutex_unlock(&(_resolver->_hosts_lock));

      std::random_shuffle(whitelisted_addresses.begin(), whitelisted_addresses.end());
      std::random_shuffle(unhealthy_addresses.begin(), unhealthy_addresses.end());
    }

    ++_next_priority_level;
    return true;
  }
  else
  {
    TRC_DEBUG("All priority levels have been prepared and searched for targets of the desired host state.");

    return false;
  }
}

int LazySRVResolveIter::get_from_priority_level(std::vector<AddrInfo> &targets,
                                                int num_targets_to_find,
                                                const int num_requested_targets,
                                                std::string& targets_log_str)
{
  AddrInfo ai;

  if (_gray_found && (num_targets_to_find > 0))
  {
    targets.push_back(_unprobed_gray_target);
    BaseResolver::add_target_to_log_string(targets_log_str,
                                           _unprobed_gray_target,
                                           "graylisted");

    pthread_mutex_lock(&(_resolver->_hosts_lock));
    _resolver->select_for_probing(_unprobed_gray_target);
    pthread_mutex_unlock(&(_resolver->_hosts_lock));

    _gray_found = false;
    --num_targets_to_find;
    TRC_DEBUG("Added a graylisted server for probing to targets, now have 1 of %d", num_requested_targets);
  }
  while ((num_targets_to_find > 0) && (!priority_level_complete()))
  {
    pthread_mutex_lock(&(_resolver->_hosts_lock));

    if ((size_t) _current_srv == _whitelisted_addresses_by_srv.size())
    {
      _current_srv = 0;
    }

    for (;
         ((size_t)_current_srv < _whitelisted_addresses_by_srv.size()) && (num_targets_to_find > 0);
         ++_current_srv)
    {
      std::vector<AddrInfo> &whitelisted_addresses = _whitelisted_addresses_by_srv[_current_srv];
      std::vector<AddrInfo> &unhealthy_addresses = _unhealthy_addresses_by_srv[_current_srv];

      if (!whitelisted_addresses.empty() && _whitelisted_allowed)
      {
        ai = whitelisted_addresses.back();
        whitelisted_addresses.pop_back();

        if (_resolver->host_state(ai) == BaseResolver::Host::State::WHITE)
        {
          targets.push_back(ai);
          --num_targets_to_find;

          BaseResolver::add_target_to_log_string(targets_log_str, ai, "whitelisted");
          TRC_DEBUG("Added a whitelisted server to targets, now have %ld of %d",
                    targets.size(),
                    num_requested_targets);
        }
        else if (_blacklisted_allowed)
        {
          unhealthy_addresses.push_back(ai);
          TRC_DEBUG("%s has moved from the whitelist to the blacklist since the current priority level",
                    ai.to_string().c_str());
        }
      }
      else if (!_whitelisted_allowed && _blacklisted_allowed &&
               !unhealthy_addresses.empty())
      {
        ai = unhealthy_addresses.back();
        unhealthy_addresses.pop_back();
        if (_resolver->host_state(ai) != BaseResolver::Host::State::WHITE)
        {
          targets.push_back(ai);
          --num_targets_to_find;

          BaseResolver::add_target_to_log_string(targets_log_str, ai, "unhealthy");
          TRC_DEBUG("Only blacklisted targets were requested, so added a blacklisted server to targets, now have %ld of %d",
                    targets.size(),
                    num_requested_targets);
        }
        else
        {
          TRC_DEBUG("%s has moved from the blacklist or graylist to the whitelist since the current priority level was prepared",
                    ai.to_string().c_str());
        }
      }

      if (!unhealthy_addresses.empty() && _blacklisted_allowed && _whitelisted_allowed)
      {
        ai = unhealthy_addresses.back();
        unhealthy_addresses.pop_back();
        _unhealthy_targets.push_back(ai);
      }
    }

    pthread_mutex_unlock(&(_resolver->_hosts_lock));
  }

  if (targets.size() > 0)
  {

    _search_for_gray=false;
  }

  return num_targets_to_find;
}
bool LazySRVResolveIter::priority_level_complete()
{
  bool complete = true;
  for (size_t ii = 0; ii < _whitelisted_addresses_by_srv.size(); ++ii)
  {
    if (!_whitelisted_addresses_by_srv[ii].empty() ||
        !_unhealthy_addresses_by_srv[ii].empty())
    {
      complete = false;
    }
  }

  return complete;
}

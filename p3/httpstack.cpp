#include <atomic>
#include "utils.h"
#include "httpstack.h"
#include <cstring>
#include <sys/stat.h>
#include <climits>
#include <algorithm>
#include "log.h"

const std::string BODY_OMITTED = "<Body present but not logged>";

bool HttpStack::_ev_using_pthreads = false;
HttpStack::DefaultSasLogger HttpStack::DEFAULT_SAS_LOGGER;
HttpStack::PrivateSasLogger HttpStack::PRIVATE_SAS_LOGGER;
HttpStack::ProxiedPrivateSasLogger HttpStack::PROXIED_PRIVATE_SAS_LOGGER;
HttpStack::NullSasLogger HttpStack::NULL_SAS_LOGGER;

HttpStack::HttpStack(int num_threads,
                     ExceptionHandler* exception_handler,
                     AccessLogger* access_logger,
                     LoadMonitor* load_monitor,
                     StatsInterface* stats) :
  _num_threads(num_threads),
  _exception_handler(exception_handler),
  _access_logger(access_logger),
  _load_monitor(load_monitor),
  _stats(stats),
  _evbase(nullptr),
  _evhtp(nullptr)
{
  TRC_STATUS("Constructing HTTP stack with %d threads", _num_threads);
}

HttpStack::~HttpStack()
{
  for(std::set<HandlerRegistration*>::iterator reg = _handler_registrations.begin();
      reg != _handler_registrations.end();
      ++reg)
  {
    delete *reg;
  }
}

void HttpStack::Request::send_reply(int rc, SAS::TrailId trail)
{
  _stopwatch.stop();
  _stack->send_reply(*this, rc, trail);
}

bool HttpStack::Request::get_latency(unsigned long& latency_us)
{
  return ((_track_latency) && (_stopwatch.read(latency_us)));
}

void HttpStack::send_reply_internal(Request& req, int rc, SAS::TrailId trail)
{
  TRC_VERBOSE("Sending response %d to request for URL %s, args %s", rc, req.req()->uri->path->full, req.req()->uri->query_raw);
  unsigned long latency_us = 0;
  req.get_latency(latency_us);
  log(std::string(req.req()->uri->path->full), req.method_as_str(), rc, latency_us);
  req.sas_log_tx_http_rsp(trail, rc, 0);

  evhtp_send_reply(req.req(), rc);
}


void HttpStack::send_reply(Request& req,
                           int rc,
                           SAS::TrailId trail)
{
  send_reply_internal(req, rc, trail);
  evhtp_request_resume(req.req());

  unsigned long latency_us = 0;
  if (req.get_latency(latency_us))
  {
    if (_load_monitor != NULL)
    {
      _load_monitor->request_complete(latency_us, trail);
    }

    if (_stats != NULL)
    {
      _stats->update_http_latency_us(latency_us);
    }
  }
}

void HttpStack::initialize()
{
  if (!_ev_using_pthreads)
  {
    evthread_use_pthreads();
    _ev_using_pthreads = true;
  }

  if (!_evbase)
  {
    _evbase = event_base_new();
  }

  if (!_evhtp)
  {
    _evhtp = evhtp_new(_evbase, NULL);

    struct timeval recv_timeo = { .tv_sec = 20, .tv_usec = 0 };
    evhtp_set_timeouts(_evhtp, &recv_timeo, NULL);
  }
}

void HttpStack::register_handler(const char* path,
                                 HttpStack::HandlerInterface* handler)
{
  HandlerRegistration* reg = new HandlerRegistration(this, handler);
  _handler_registrations.insert(reg);

  evhtp_callback_t* cb = evhtp_set_regex_cb(_evhtp,
                                            path,
                                            handler_callback_fn,
                                            (void*)reg);
  if (cb == NULL)
  {
    throw Exception("evhtp_set_cb", 0); 
  }
}

void HttpStack::register_default_handler(HttpStack::HandlerInterface* handler)
{
  HandlerRegistration* reg = new HandlerRegistration(this, handler);
  _handler_registrations.insert(reg);

  evhtp_set_gencb(_evhtp,
                  handler_callback_fn,
                  (void*)reg);
}

void HttpStack::bind_tcp_socket(const std::string& bind_address,
                                unsigned short port)
{
  TRC_STATUS("Binding HTTP TCP socket: address=%s, port=%d", bind_address.c_str(), port);

  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;    
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* servinfo = NULL;

  std::string full_bind_address = bind_address;
  const int error_num = getaddrinfo(bind_address.c_str(), NULL, &hints, &servinfo);

  if ((error_num == 0) &&
      (servinfo->ai_family == AF_INET))
  {
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,
              &(((struct sockaddr_in*)servinfo->ai_addr)->sin_addr),
              dest_str,
              INET_ADDRSTRLEN);
    full_bind_address = dest_str;
  }
  else if ((error_num == 0) &&
           (servinfo->ai_family == AF_INET6))
  {
    char dest_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,
              &(((struct sockaddr_in6*)servinfo->ai_addr)->sin6_addr),
              dest_str,
              INET6_ADDRSTRLEN);
    full_bind_address = dest_str;
    full_bind_address = "ipv6:" + full_bind_address;
  }

  freeaddrinfo(servinfo);

  int rc = evhtp_bind_socket(_evhtp, full_bind_address.c_str(), port, 1024);
  if (rc != 0)
  {
    TRC_ERROR("evhtp_bind_socket failed with address %s and port %d",
              full_bind_address.c_str(),
              port);
    throw Exception("evhtp_bind_socket (tcp)", rc);
  
  }

}

void HttpStack::bind_unix_socket(const std::string& bind_path)
{
  TRC_STATUS("Binding HTTP unix socket: path=%s", bind_path.c_str());

  ::remove(bind_path.c_str());

  std::string full_bind_address = "unix:" + bind_path;

  int rc = evhtp_bind_socket(_evhtp, full_bind_address.c_str(), 0, 1024);
  if (rc != 0)
  {

    TRC_ERROR("evhtp_bind_socket failed with path %s",
              full_bind_address.c_str());
    throw Exception("evhtp_bind_socket (unix)", rc);

  }

  chmod(bind_path.c_str(), 0777);
}

void HttpStack::start(evhtp_thread_init_cb init_cb)
{
  int rc = evhtp_use_threads(_evhtp, init_cb, _num_threads, this);
  if (rc != 0)
  {
    throw Exception("evhtp_use_threads", rc); 
  }

  rc = pthread_create(&_event_base_thread, NULL, event_base_thread_fn, this);
  if (rc != 0)
  {
    TRC_ERROR("pthread_create failed in HTTPStack creation");
    throw Exception("pthread_create", rc);
  }
}

void HttpStack::stop()
{
  TRC_STATUS("Stopping HTTP stack");
  event_base_loopbreak(_evbase);
  evhtp_unbind_socket(_evhtp);
}

void HttpStack::wait_stopped()
{
  TRC_STATUS("Waiting for HTTP stack to stop");
  pthread_join(_event_base_thread, NULL);
  evhtp_free(_evhtp);
  _evhtp = NULL;
  event_base_free(_evbase);
  _evbase = NULL;
}

void HttpStack::handler_callback_fn(evhtp_request_t* req, void* handler_reg_param)
{
  HandlerRegistration* handler_reg =
    static_cast<HandlerRegistration*>(handler_reg_param);
  handler_reg->stack->handler_callback(req, handler_reg->handler);
}

void HttpStack::handler_callback(evhtp_request_t* req,
                                 HttpStack::HandlerInterface* handler)
{
  Request request(this, req);

  request.set_sas_logger(handler->sas_logger(request));

  SAS::TrailId trail = SAS::new_trail(0);
  request.sas_log_rx_http_req(trail, 0);

  if (_stats != NULL)
  {
    _stats->incr_http_incoming_requests();
  }

  if ((_load_monitor == NULL) || _load_monitor->admit_request(trail))
  {
    evhtp_request_pause(req);
    TRC_VERBOSE("Process request for URL %s, args %s",
                req->uri->path->full,
                req->uri->query_raw);

    CW_TRY
    {
      handler->process_request(request, trail);
    }
    CW_EXCEPT(_exception_handler)
    {
      send_reply_internal(request, 500, trail);

      if (_num_threads == 1)
      {
        exit(1);
      }
    }
    CW_END
  }
  else
  {
    TRC_DEBUG("Rejecting request for URL %s, args %s with 503 due to overload",
                req->uri->path->full,
                req->uri->query_raw);

    request.sas_log_overload(trail,
                             503,
                             _load_monitor->get_target_latency_us(),
                             _load_monitor->get_current_latency_us(),
                             _load_monitor->get_rate_limit(),
                             0);
    send_reply_internal(request, 503, trail);

    if (_stats != NULL)
    {
      _stats->incr_http_rejected_overload();
    }
  }
}

void* HttpStack::event_base_thread_fn(void* http_stack_ptr)
{
  ((HttpStack*)http_stack_ptr)->event_base_thread_fn();
  return NULL;
}

void HttpStack::event_base_thread_fn()
{
  event_base_loop(_evbase, 0);
}

void HttpStack::record_penalty()
{
  if (_load_monitor != NULL)
  {
    _load_monitor->incr_penalties();
  }
}

std::string HttpStack::Request::get_rx_body()
{
  if (!_rx_body_set)
  {
    _rx_body = evbuffer_to_string(_req->buffer_in);
  }
  return _rx_body;
}

std::string HttpStack::Request::get_tx_body()
{
  return evbuffer_to_string(_req->buffer_out);
}

std::string HttpStack::Request::get_rx_header()
{
  return evbuffer_to_string(_req->header_buffer_in);
}

std::string HttpStack::Request::get_tx_header(int rc)
{
  std::string hdr;
  evbuffer* eb = evbuffer_new();

  if (evhtp_get_response_header(_req, rc, eb) == 0)
  {
    hdr = evbuffer_to_string(eb);
  }

  evbuffer_free(eb);
  return hdr;
}

std::string HttpStack::Request::get_rx_message()
{
  return get_rx_header() + get_rx_body();
}

std::string HttpStack::Request::get_tx_message(int rc)
{
  return get_tx_header(rc) + get_tx_body();
}

std::string HttpStack::Request::evbuffer_to_string(evbuffer* eb)
{
  std::string s;
  size_t len = evbuffer_get_length(eb);
  void* buf = evbuffer_pullup(eb, len);

  if (buf != NULL)
  {
    s.assign((char*)buf, len);
  }

  return s;
}


bool HttpStack::Request::get_remote_ip_port(std::string& ip, unsigned short& port)
{
  bool rc = false;
  char ip_buf[64];

  if (evhtp_get_remote_ip_port(evhtp_request_get_connection(_req),
                               ip_buf,
                               sizeof(ip_buf),
                               &port) == 0)
  {
    ip.assign(ip_buf);
    rc = true;
  }
  return rc;
}

bool HttpStack::Request::get_x_real_ip_port(std::string& ip, unsigned short& port)
{
  bool rc = false;
  std::string real_ip = header("X-Real-Ip");
  TRC_DEBUG("Real IP: %s", real_ip.c_str());

  if (real_ip != "")
  {
    rc = true;
    ip = real_ip;
    std::string port_s = header("X-Real-Port");
    int port_i;
    port = 0;

    if (port_s != "" && (std::all_of(port_s.begin(), port_s.end(), ::isdigit)))
    {
      try
      {
        port_i = std::stoi(port_s);
        if (port_i >= 0 && port_i <= USHRT_MAX)
        {
          port = (short)port_i;
        }
      }
      catch (...)
      {
      }
    }
  }

  return rc;
}

bool HttpStack::Request::get_local_ip_port(std::string& ip, unsigned short& port)
{
  bool rc = false;
  char ip_buf[64];

  if (evhtp_get_local_ip_port(evhtp_request_get_connection(_req),
                              ip_buf,
                              sizeof(ip_buf),
                              &port) == 0)
  {
    ip.assign(ip_buf);
    rc = true;
  }
  return rc;
}
void HttpStack::SasLogger::log_correlators(SAS::TrailId trail,
                                          Request& req,
                                          uint32_t instance_id)
{

  log_correlator(trail,
                 req,
                 instance_id,
                 SASEvent::HTTP_BRANCH_HEADER_NAME,
                 MARKER_ID_VIA_BRANCH_PARAM);

  log_correlator(trail,
                 req,
                 instance_id,
                 SASEvent::HTTP_SPAN_ID,
                 MARKER_ID_GENERIC_CORRELATOR);
}

void HttpStack::SasLogger::log_correlator(SAS::TrailId trail,
                                          Request& req,
                                          uint32_t instance_id,
                                          std::string header_name,
                                          int marker_type) {

  std::string correlator = req.header(header_name);

  if (correlator != "") {
    SAS::Marker corr_marker(trail, marker_type, instance_id);
    corr_marker.add_var_param(correlator);

    if (marker_type == MARKER_ID_GENERIC_CORRELATOR) {
      corr_marker.add_static_param(
        static_cast<uint32_t>(UniquenessScopes::UUID_RFC4122));
    }

    SAS::report_marker(corr_marker, SAS::Marker::Scope::Trace, false);
  }
}

void HttpStack::SasLogger::log_req_event(SAS::TrailId trail,
                                         Request& req,
                                         uint32_t instance_id,
                                         SASEvent::HttpLogLevel level,
                                         bool omit_body)
{
  int event_id = ((level == SASEvent::HttpLogLevel::PROTOCOL) ?
                  SASEvent::RX_HTTP_REQ : SASEvent::RX_HTTP_REQ_DETAIL);
  SAS::Event event(trail, event_id, instance_id);

  add_ip_addrs_and_ports(event, req);
  event.add_static_param(req.method());
  event.add_var_param(req.full_path());

  if (!omit_body)
  {
    event.add_var_param(req.get_rx_message());
  }
  else
  {
    if (req.get_rx_body().empty())
    {
      event.add_var_param(req.get_rx_header());
    }
    else
    {
      event.add_var_param(req.get_rx_header() + BODY_OMITTED);
    }
  }

  SAS::report_event(event);
}

void HttpStack::SasLogger::log_rsp_event(SAS::TrailId trail,
                                         Request& req,
                                         int rc,
                                         uint32_t instance_id,
                                         SASEvent::HttpLogLevel level,
                                         bool omit_body)
{
  int event_id = ((level == SASEvent::HttpLogLevel::PROTOCOL) ?
                  SASEvent::TX_HTTP_RSP : SASEvent::TX_HTTP_RSP_DETAIL);
  SAS::Event event(trail, event_id, instance_id);

  add_ip_addrs_and_ports(event, req);
  event.add_static_param(req.method());
  event.add_static_param(rc);
  event.add_var_param(req.full_path());

  if (!omit_body)
  {
    event.add_var_param(req.get_tx_message(rc));
  }
  else
  {
    if (req.get_tx_body().empty())
    {
      event.add_var_param(req.get_tx_header(rc));
    }
    else
    {
      event.add_var_param(req.get_tx_header(rc) + BODY_OMITTED);
    }
  }

  SAS::report_event(event);
}

void HttpStack::SasLogger::log_overload_event(SAS::TrailId trail,
                                              Request& req,
                                              int rc,
                                              int target_latency,
                                              int current_latency,
                                              float rate_limit,
                                              uint32_t instance_id,
                                              SASEvent::HttpLogLevel level)
{
  int event_id = ((level == SASEvent::HttpLogLevel::PROTOCOL) ?
                  SASEvent::HTTP_REJECTED_OVERLOAD :
                  SASEvent::HTTP_REJECTED_OVERLOAD_DETAIL);
  SAS::Event event(trail, event_id, instance_id);
  event.add_static_param(req.method());
  event.add_static_param(rc);
  event.add_static_param(target_latency);
  event.add_static_param(current_latency);
  event.add_static_param(rate_limit);
  event.add_var_param(req.full_path());
  SAS::report_event(event);
}

void HttpStack::SasLogger::add_ip_addrs_and_ports(SAS::Event& event, Request& req)
{
  std::string ip;
  unsigned short port;

  if (req.get_remote_ip_port(ip, port))
  {
    event.add_var_param(ip);
    event.add_static_param(port);
  }
  else
  {
    event.add_var_param("unknown");
    event.add_static_param(0);
  }

  if (req.get_local_ip_port(ip, port))
  {
    event.add_var_param(ip);
    event.add_static_param(port);
  }
  else
  {
    event.add_var_param("unknown");
    event.add_static_param(0);
  }
}

void HttpStack::DefaultSasLogger::sas_log_rx_http_req(SAS::TrailId trail,
                                                      HttpStack::Request& req,
                                                      uint32_t instance_id)
{
  log_correlators(trail, req, instance_id);
  log_req_event(trail, req, instance_id);
}


void HttpStack::DefaultSasLogger::sas_log_tx_http_rsp(SAS::TrailId trail,
                                                      HttpStack::Request& req,
                                                      int rc,
                                                      uint32_t instance_id)
{
  log_rsp_event(trail, req, rc, instance_id);
}

void HttpStack::DefaultSasLogger::sas_log_overload(SAS::TrailId trail,
                                                   HttpStack::Request& req,
                                                   int rc,
                                                   int target_latency,
                                                   int current_latency,
                                                   float rate_limit,
                                                   uint32_t instance_id)
{
  log_overload_event(trail, req, rc, target_latency, current_latency, rate_limit, instance_id);
}

void HttpStack::PrivateSasLogger::sas_log_rx_http_req(SAS::TrailId trail,
                                                      HttpStack::Request& req,
                                                      uint32_t instance_id)
{
  log_correlators(trail, req, instance_id);
  log_req_event(trail, req, instance_id, SASEvent::HttpLogLevel::PROTOCOL, true);
}

void HttpStack::PrivateSasLogger::sas_log_tx_http_rsp(SAS::TrailId trail,
                                                      HttpStack::Request& req,
                                                      int rc,
                                                      uint32_t instance_id)
{
  log_rsp_event(trail, req, rc, instance_id, SASEvent::HttpLogLevel::PROTOCOL, true);
}
void HttpStack::ProxiedPrivateSasLogger::add_ip_addrs_and_ports(SAS::Event& event, Request& req)
{
  std::string ip;
  unsigned short port;
  if (req.get_x_real_ip_port(ip, port))
  {
    event.add_var_param(ip);
    event.add_static_param(port);
  }
  else if (req.get_remote_ip_port(ip, port))
  {
    event.add_var_param(ip);
    event.add_static_param(port);
  }
  else
  {
    event.add_var_param("unknown");
    event.add_static_param(0);
  }

  if (req.get_local_ip_port(ip, port))
  {
    event.add_var_param(ip);
    event.add_static_param(port);
  }
  else
  {
    event.add_var_param("unknown");
    event.add_static_param(0);
  }
}

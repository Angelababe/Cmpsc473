#include <atomic>
#include <curl/curl.h>
#include <cassert>
#include <iostream>
#include <map>
#include "cpp_common_pd_definitions.h"
#include "utils.h"
#include "log.h"
#include "sas.h"
#include "httpclient.h"
#include "http_request.h"
#include "load_monitor.h"
#include "random_uuid.h"

static const int MAX_TARGETS = 5;

HttpClient::HttpClient(bool assert_user,
                       HttpResolver* resolver,
                       SNMP::IPCountTable* stat_table,
                       LoadMonitor* load_monitor,
                       SASEvent::HttpLogLevel sas_log_level,
                       BaseCommunicationMonitor* comm_monitor,
                       bool should_omit_body,
                       bool remote_connection,
                       long timeout_ms,
                       bool log_display_address,
                       std::string server_display_address,
                       const std::string& source_address) :
  _assert_user(assert_user),
  _resolver(resolver),
  _load_monitor(load_monitor),
  _sas_log_level(sas_log_level),
  _comm_monitor(comm_monitor),
  _stat_table(stat_table),
  _conn_pool(load_monitor, stat_table, remote_connection, timeout_ms, source_address),
  _should_omit_body(should_omit_body),
  _log_display_address(log_display_address),
  _server_display_address(server_display_address)
{
  pthread_key_create(&_uuid_thread_local, cleanup_uuid);
  pthread_mutex_init(&_lock, NULL);
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

HttpClient::HttpClient(bool assert_user,
                       HttpResolver* resolver,
                       SASEvent::HttpLogLevel sas_log_level,
                       BaseCommunicationMonitor* comm_monitor) :
  HttpClient(assert_user,
             resolver,
             NULL,
             NULL,
             sas_log_level,
             comm_monitor)
{
}

HttpClient::~HttpClient()
{
  RandomUUIDGenerator* uuid_gen =
    (RandomUUIDGenerator*)pthread_getspecific(_uuid_thread_local);

  if (uuid_gen != NULL)
  {
    pthread_setspecific(_uuid_thread_local, NULL);
    cleanup_uuid(uuid_gen); uuid_gen = NULL;
  }

  pthread_key_delete(_uuid_thread_local);
}
HTTPCode HttpClient::curl_code_to_http_code(CURL* curl, CURLcode code)
{
  switch (code)
  {
  case CURLE_OK:
  {
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    return http_code;
  }
  case CURLE_URL_MALFORMAT:
  case CURLE_NOT_BUILT_IN:
    return HTTP_BAD_REQUEST;
  case CURLE_REMOTE_FILE_NOT_FOUND:
    return HTTP_NOT_FOUND;
  case CURLE_COULDNT_RESOLVE_PROXY:
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_COULDNT_CONNECT:
  case CURLE_AGAIN:
    return HTTP_NOT_FOUND;
  case CURLE_OPERATION_TIMEDOUT:
    return HTTP_SERVER_UNAVAILABLE;
  default:
    return HTTP_SERVER_ERROR;
  }
}

std::string HttpClient::request_type_to_string(RequestType request_type)
{
  switch (request_type) {
  case RequestType::DELETE:
    return "DELETE";
  case RequestType::PUT:
    return "PUT";
  case RequestType::POST:
    return "POST";
  case RequestType::GET:
    return "GET";
  default:
    return "UNKNOWN";
  }
}
HttpResponse HttpClient::send_request(const HttpRequest& req)
{
  std::string url = req._scheme + "://" + req._server + req._path;

  std::string body;
  std::map<std::string, std::string> headers;

  HTTPCode rc = send_request(req._method,
                             url,
                             req._body,
                             body,
                             req._username,
                             req._trail,
                             req._headers,
                             &headers,
                             req._allowed_host_state);

  return HttpResponse(rc,
                      body,
                      headers);
}

HTTPCode HttpClient::send_request(RequestType request_type,
                                  const std::string& url,
                                  std::string body,
                                  std::string& doc,
                                  const std::string& username,
                                  SAS::TrailId trail,
                                  std::vector<std::string> headers_to_add,
                                  std::map<std::string, std::string>* response_headers,
                                  int allowed_host_state)
{
  HTTPCode http_code;
  CURLcode rc;

  std::string method_str = request_type_to_string(request_type);

  boost::uuids::uuid uuid = get_random_uuid();
  std::string uuid_str = boost::uuids::to_string(uuid);

  SAS::Marker corr_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 0);
  corr_marker.add_var_param(uuid_str);
  SAS::report_marker(corr_marker, SAS::Marker::Scope::Trace, false);

  std::string scheme;
  std::string server;
  std::string path;
  if (!Utils::parse_http_url(url, scheme, server, path))
  {
    TRC_ERROR("%s could not be parsed as a URL : fatal",
              url.c_str());
    return HTTP_BAD_REQUEST;
  }

  std::string host = host_from_server(scheme, server);
  int port = port_from_server(scheme, server);

  BaseAddrIterator* target_it = _resolver->resolve_iter(host, port, trail, allowed_host_state);
  IP46Address dummy_address;
  bool host_is_ip = Utils::parse_ip_target(host, dummy_address);

  int num_http_503_responses = 0;
  int num_http_504_responses = 0;
  int num_timeouts_or_io_errors = 0;

  const char *remote_ip = NULL;
  rc = CURLE_COULDNT_RESOLVE_HOST;
  http_code = HTTP_NOT_FOUND;

  AddrInfo target;

  int attempts = 0;
  while (target_it->next(target) || attempts == 1)
  {
    attempts++;

    ConnectionHandle<CURL*> conn_handle = _conn_pool.get_connection(target);
    CURL* curl = conn_handle.get_connection();

    struct curl_slist* extra_headers = build_headers(headers_to_add,
                                                     !body.empty(),
                                                     _assert_user,
                                                     username,
                                                     uuid_str);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, extra_headers);

    set_curl_options_general(curl, body, doc);

    std::map<std::string, std::string> internal_rsp_hdrs;

    if (!response_headers)
    {
      response_headers = &internal_rsp_hdrs;
    }

    set_curl_options_response(curl, response_headers);

    set_curl_options_request(curl, request_type);

    char buf[100];
    remote_ip = inet_ntop(target.address.af,
                          &target.address.addr,
                          buf,
                          sizeof(buf));

    curl_slist *host_resolve = NULL;
    curl_easy_getinfo(curl, CURLINFO_PRIVATE, &host_resolve);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, NULL);

    if (!host_is_ip)
    {
      std::string resolve_addr =
        host + ":" + std::to_string(port) + ":" + remote_ip;
      host_resolve = curl_slist_append(host_resolve, resolve_addr.c_str());
      TRC_DEBUG("Set CURLOPT_RESOLVE: %s", resolve_addr.c_str());
    }
    if (host_resolve != NULL)
    {
      curl_easy_setopt(curl, CURLOPT_RESOLVE, host_resolve);
    }
    std::string curl_target = scheme + "://" + host + ":" + std::to_string(port) + path;
    curl_easy_setopt(curl, CURLOPT_URL, curl_target.c_str());

    Recorder recorder;
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &recorder);

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    void* host_context = set_curl_options_host(curl, host, port);

    SAS::Timestamp req_timestamp = SAS::get_current_timestamp();

    doc.clear();
    TRC_DEBUG("Sending HTTP request : %s (trying %s)", url.c_str(), remote_ip);

    struct timespec timespec;
    clock_gettime(CLOCK_REALTIME, &timespec);

    CW_IO_STARTS("HTTP request to " + url)
    {
      rc = curl_easy_perform(curl);
    }
    CW_IO_COMPLETES()

    if (recorder.request.length() > 0)
    {
      sas_log_http_req(trail, curl, method_str, url, recorder.request, req_timestamp, 0);
    }

    if (host_resolve != NULL)
    {
      curl_slist_free_all(host_resolve);
      host_resolve = NULL;
    }

    if (!host_is_ip)
    {
      std::string resolve_remove_addr =
        std::string("-") + host + ":" + std::to_string(port);
      host_resolve = curl_slist_append(NULL, resolve_remove_addr.c_str());
      curl_easy_setopt(curl, CURLOPT_PRIVATE, host_resolve);
    }

    long http_rc = 0;
    if (rc == CURLE_OK)
    {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
      sas_log_http_rsp(trail, curl, http_rc, method_str, url, recorder.response, 0);
      TRC_DEBUG("Received HTTP response: status=%d, doc=%s", http_rc, doc.c_str());
      if (http_rc >= 400)
      {
        TRC_VERBOSE("Received HTTP response %d from server %s for URL %s",
                  http_rc,
                  remote_ip,
                  url.c_str());
      }

    }
    else
    {
      const char* error = curl_easy_strerror(rc);
      struct tm dt;
      gmtime_r(&timespec.tv_sec, &dt);

      TRC_WARNING("%s failed at server %s : %d: %s - %s trail: %d sent at: "
                  "%2.2d-%2.2d-%4.4d %2.2d:%2.2d:%2.2d.%3.3d UTC ",
                  url.c_str(),
                  remote_ip,
                  rc,
                  error,
                  errbuf,
                  trail,
                  dt.tm_mday, (dt.tm_mon+1), (dt.tm_year + 1900),
                  dt.tm_hour, dt.tm_min, dt.tm_min, (int)(timespec.tv_nsec / 1000000));

      sas_log_curl_error(trail,
                         remote_ip,
                         target.port,
                         method_str,
                         url,
                         rc,
                         0,
                         strlen(errbuf) > 0 ? errbuf : error);
    }

    http_code = curl_code_to_http_code(curl, rc);

    curl_slist_free_all(extra_headers);

    cleanup_host_context(host_context);

    if ((rc == CURLE_OK) && !(http_rc >= 400))
    {
      _resolver->success(target);
      break;
    }
    else
    {
      if ((!(http_rc >= 400)) &&
          (rc != CURLE_REMOTE_FILE_NOT_FOUND) &&
          (rc != CURLE_REMOTE_ACCESS_DENIED))
      {
        TRC_DEBUG("Blacklist on connection failure");
        conn_handle.set_return_to_pool(false);
        _resolver->blacklist(target);
      }
      else if (http_rc == 503)
      {
        TRC_DEBUG("Have 503 failure");
        std::map<std::string, std::string>::iterator retry_after_header =
                                          response_headers->find("retry-after");
        int retry_after = 0;

        if (retry_after_header != response_headers->end())
        {
          TRC_DEBUG("Try to parse retry after value");
          std::string retry_after_val = retry_after_header->second;
          retry_after = atoi(retry_after_val.c_str());

          if (retry_after == 0)
          {
            TRC_WARNING("Failed to parse Retry-After value: %s", retry_after_val.c_str());
            sas_log_bad_retry_after_value(trail, retry_after_val, 0);
          }
        }

        if (retry_after > 0)
        {
          TRC_DEBUG("Have retry after value %d", retry_after);
          conn_handle.set_return_to_pool(false);
          _resolver->blacklist(target, retry_after);
        }
        else
        {
          _resolver->success(target);
        }
      }
      else
      {
        _resolver->success(target);
      }

      bool fatal_http_error = false;

      if (http_rc >= 400)
      {
        if (http_rc == 503)
        {
          num_http_503_responses++;
        }
        else if (http_rc == 504)
        {
          num_http_504_responses++;
        }
        else
        {
          fatal_http_error = true;
        }
      }
      else if ((rc == CURLE_REMOTE_FILE_NOT_FOUND) ||
               (rc == CURLE_REMOTE_ACCESS_DENIED))
      {
        fatal_http_error = true;
      }
      else if ((rc == CURLE_OPERATION_TIMEDOUT) ||
               (rc == CURLE_SEND_ERROR) ||
               (rc == CURLE_RECV_ERROR))
      {
        num_timeouts_or_io_errors++;
      }
      if ((num_http_503_responses + num_timeouts_or_io_errors >= 2) ||
          (num_http_504_responses >= 1) ||
          fatal_http_error)
      {
        HttpErrorResponseTypes reason = fatal_http_error ?
                                        HttpErrorResponseTypes::Permanent :
                                        HttpErrorResponseTypes::Temporary;
        sas_log_http_abort(trail, reason, 0);
        break;
      }
    }
  }

  delete target_it;

  if (attempts == 0)
  {
    TRC_INFO("Failed to resolve hostname for %s to %s", method_str.c_str(), url.c_str());
    SAS::Event event(trail,
                     ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                       SASEvent::HTTP_HOSTNAME_DID_NOT_RESOLVE :
                       SASEvent::HTTP_HOSTNAME_DID_NOT_RESOLVE_DETAIL),
                     0);
    event.add_var_param(method_str);
    event.add_var_param(Utils::url_unescape(url));
    SAS::report_event(event);
  }
  if (((num_http_503_responses >= 2) ||
       (num_http_504_responses >= 1)) &&
      (_load_monitor != NULL))
  {
    _load_monitor->incr_penalties();
  }

  struct timespec tp;
  int rv = clock_gettime(CLOCK_MONOTONIC, &tp);
  assert(rv == 0);
  unsigned long now_ms = tp.tv_sec * 1000 + (tp.tv_nsec / 1000000);

  if (rc == CURLE_OK)
  {
    if (_comm_monitor)
    {
      if (num_http_503_responses >= 2)
      {
        _comm_monitor->inform_failure(now_ms); 
      }
      else
      {
        _comm_monitor->inform_success(now_ms);
      }
    }
  }
  else
  {
    if (_comm_monitor)
    {
      _comm_monitor->inform_failure(now_ms);
    }
  }

  return http_code;
}

struct curl_slist* HttpClient::build_headers(std::vector<std::string> headers_to_add,
                                             bool has_body,
                                             bool assert_user,
                                             const std::string& username,
                                             std::string uuid_str)
{
  struct curl_slist* extra_headers = NULL;

  if (has_body)
  {
    extra_headers = curl_slist_append(extra_headers, "Content-Type: application/json");
  }

  extra_headers = curl_slist_append(extra_headers,
                                    (SASEvent::HTTP_BRANCH_HEADER_NAME + ": " + uuid_str).c_str());

  extra_headers = curl_slist_append(extra_headers, "Expect:");


  for (std::vector<std::string>::const_iterator i = headers_to_add.begin();
       i != headers_to_add.end();
       ++i)
  {
    extra_headers = curl_slist_append(extra_headers, (*i).c_str());
  }

  if (assert_user)
  {
    extra_headers = curl_slist_append(extra_headers,
                                      ("X-XCAP-Asserted-Identity: " + username).c_str());
  }
  return extra_headers;
}

void HttpClient::set_curl_options_general(CURL* curl,
                                          std::string body,
                                          std::string& doc)
{
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &doc);

  if (!body.empty())
  {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
  }
}

void HttpClient::set_curl_options_response(CURL* curl,
                               std::map<std::string, std::string>* response_headers)
{
  if (response_headers)
  {
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &HttpClient::write_headers);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, response_headers);
  }
}

void HttpClient::set_curl_options_request(CURL* curl, RequestType request_type)
{
  switch (request_type)
  {
  case RequestType::DELETE:
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    break;
  case RequestType::PUT:
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    break;
  case RequestType::POST:
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    break;
  case RequestType::GET:
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    break;
  }
}

size_t HttpClient::string_store(void* ptr, size_t size, size_t nmemb, void* stream)
{
  ((std::string*)stream)->append((char*)ptr, size * nmemb);
  return (size * nmemb);
}

size_t HttpClient::write_headers(void *ptr, size_t size, size_t nmemb, std::map<std::string, std::string> *headers)
{
  char* headerLine = reinterpret_cast<char *>(ptr);

  std::string headerString(headerLine, (size * nmemb));

  std::string key;
  std::string val;

  size_t colon_loc = headerString.find(":");
  if (colon_loc == std::string::npos)
  {
    key = headerString;
    val = "";
  }
  else
  {
    key = headerString.substr(0, colon_loc);
    val = headerString.substr(colon_loc + 1, std::string::npos);
  }

  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
  val.erase(std::remove_if(val.begin(), val.end(), ::isspace), val.end());

  TRC_DEBUG("Received header %s with value %s", key.c_str(), val.c_str());
  TRC_DEBUG("Header pointer: %p", headers);
  (*headers)[key] = val;

  return size * nmemb;
}

void HttpClient::cleanup_uuid(void *uuid_gen)
{
  delete (RandomUUIDGenerator*)uuid_gen; uuid_gen = NULL;
}

boost::uuids::uuid HttpClient::get_random_uuid()
{
  RandomUUIDGenerator* uuid_gen;
  uuid_gen =
    (RandomUUIDGenerator*)pthread_getspecific(_uuid_thread_local);

  if (uuid_gen == NULL)
  {
    uuid_gen = new RandomUUIDGenerator();
    pthread_setspecific(_uuid_thread_local, uuid_gen);
  }

  return (*uuid_gen)();
}

void HttpClient::sas_add_ip(SAS::Event& event, CURL* curl, CURLINFO info)
{
  char* ip;

  if (curl_easy_getinfo(curl, info, &ip) == CURLE_OK)
  {
    if ((_log_display_address) && (info == CURLINFO_PRIMARY_IP))
    {
      event.add_var_param(_server_display_address);
    }
    else
    {
      event.add_var_param(ip);
    }
  }
  else
  {
    event.add_var_param("unknown"); 
  }
}

void HttpClient::sas_add_port(SAS::Event& event, CURL* curl, CURLINFO info)
{
  long port;

  if (curl_easy_getinfo(curl, info, &port) == CURLE_OK)
  {
    event.add_static_param(port);
  }
  else
  {
    event.add_static_param(0); 
  }
}

void HttpClient::sas_add_ip_addrs_and_ports(SAS::Event& event,
                                                CURL* curl)
{
  sas_add_ip(event, curl, CURLINFO_PRIMARY_IP);
  sas_add_port(event, curl, CURLINFO_PRIMARY_PORT);

  sas_add_ip(event, curl, CURLINFO_LOCAL_IP);
  sas_add_port(event, curl, CURLINFO_LOCAL_PORT);
}

std::string HttpClient::get_obscured_message_to_log(const std::string& message)
{
  std::string message_to_log;
  std::size_t body_pos = message.find(HEADERS_END);
  std::string headers = message.substr(0, body_pos);

  if (body_pos + 4 == message.length())
  {
    message_to_log = message;
  }
  else
  {
    message_to_log = headers + BODY_OMITTED;
  }

  return message_to_log;
}

void HttpClient::sas_log_http_req(SAS::TrailId trail,
                                  CURL* curl,
                                  const std::string& method_str,
                                  const std::string& url,
                                  const std::string& request_bytes,
                                  SAS::Timestamp timestamp,
                                  uint32_t instance_id)
{
  if (_sas_log_level != SASEvent::HttpLogLevel::NONE)
  {
    int event_id = ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                    SASEvent::TX_HTTP_REQ : SASEvent::TX_HTTP_REQ_DETAIL);
    SAS::Event event(trail, event_id, instance_id);

    sas_add_ip_addrs_and_ports(event, curl);

    if (!_should_omit_body)
    {
      event.add_var_param(request_bytes);
    }
    else
    {
      std::string message_to_log = get_obscured_message_to_log(request_bytes);
      event.add_var_param(message_to_log);
    }

    event.add_var_param(method_str);
    event.add_var_param(Utils::url_unescape(url));

    event.set_timestamp(timestamp);
    SAS::report_event(event);
  }
}

void HttpClient::sas_log_http_rsp(SAS::TrailId trail,
                                  CURL* curl,
                                  long http_rc,
                                  const std::string& method_str,
                                  const std::string& url,
                                  const std::string& response_bytes,
                                  uint32_t instance_id)
{
  if (_sas_log_level != SASEvent::HttpLogLevel::NONE)
  {
    int event_id = ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                    SASEvent::RX_HTTP_RSP : SASEvent::RX_HTTP_RSP_DETAIL);
    SAS::Event event(trail, event_id, instance_id);

    sas_add_ip_addrs_and_ports(event, curl);
    event.add_static_param(http_rc);

    if (!_should_omit_body)
    {
      event.add_var_param(response_bytes);
    }
    else
    {
      std::string message_to_log = get_obscured_message_to_log(response_bytes);
      event.add_var_param(message_to_log);
    }

    event.add_var_param(method_str);
    event.add_var_param(Utils::url_unescape(url));

    SAS::report_event(event);
  }
}

void HttpClient::sas_log_http_abort(SAS::TrailId trail,
                                    HttpErrorResponseTypes reason,
                                    uint32_t instance_id)
{
  int event_id = ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                    SASEvent::HTTP_ABORT : SASEvent::HTTP_ABORT_DETAIL);
  SAS::Event event(trail, event_id, instance_id);
  event.add_static_param(static_cast<uint32_t>(reason));
  SAS::report_event(event);
}

void HttpClient::sas_log_curl_error(SAS::TrailId trail,
                                    const char* remote_ip_addr,
                                    unsigned short remote_port,
                                    const std::string& method_str,
                                    const std::string& url,
                                    CURLcode code,
                                    uint32_t instance_id,
                                    const char* error)
{
  if (_sas_log_level != SASEvent::HttpLogLevel::NONE)
  {
    int event_id = ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                    SASEvent::HTTP_REQ_ERROR : SASEvent::HTTP_REQ_ERROR_DETAIL);
    SAS::Event event(trail, event_id, instance_id);

    event.add_static_param(remote_port);
    event.add_static_param(code);
    event.add_var_param(remote_ip_addr);
    event.add_var_param(method_str);
    event.add_var_param(Utils::url_unescape(url));
    event.add_var_param(error);

    SAS::report_event(event);
  }
}

void HttpClient::sas_log_bad_retry_after_value(SAS::TrailId trail,
                                               const std::string value,
                                               uint32_t instance_id)
{
  if (_sas_log_level != SASEvent::HttpLogLevel::NONE)
  {
    int event_id = ((_sas_log_level == SASEvent::HttpLogLevel::PROTOCOL) ?
                    SASEvent::HTTP_BAD_RETRY_AFTER_VALUE : SASEvent::HTTP_BAD_RETRY_AFTER_VALUE_DETAIL);
    SAS::Event event(trail, event_id, instance_id);
    event.add_var_param(value.c_str());
    SAS::report_event(event);
  }
}

void HttpClient::host_port_from_server(const std::string& scheme,
                                       const std::string& server,
                                       std::string& host,
                                       int& port)
{
  std::string server_copy = server;
  Utils::trim(server_copy);
  size_t colon_idx;
  if (((server_copy[0] != '[') ||
       (server_copy[server_copy.length() - 1] != ']')) &&
      ((colon_idx = server_copy.find_last_of(':')) != std::string::npos))
  {
    host = server_copy.substr(0, colon_idx);
    port = stoi(server_copy.substr(colon_idx + 1));
  }
  else
  {
    host = server_copy;
    port = (scheme == "https") ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
  }
}

std::string HttpClient::host_from_server(const std::string& scheme,
                                         const std::string& server)
{
  std::string host;
  int port;
  host_port_from_server(scheme, server, host, port);
  return host;
}

int HttpClient::port_from_server(const std::string& scheme,
                                 const std::string& server)
{
  std::string host;
  int port;
  host_port_from_server(scheme, server, host, port);
  return port;
}

HttpClient::Recorder::Recorder() {}

HttpClient::Recorder::~Recorder() {}

int HttpClient::Recorder::debug_callback(CURL *handle,
                                         curl_infotype type,
                                         char *data,
                                         size_t size,
                                         void *userptr)
{
  return ((Recorder*)userptr)->record_data(type, data, size);
}

int HttpClient::Recorder::record_data(curl_infotype type,
                                      char* data,
                                      size_t size)
{
  switch (type)
  {
  case CURLINFO_HEADER_IN:
  case CURLINFO_DATA_IN:
    response.append(data, size);
    break;

  case CURLINFO_HEADER_OUT:
  case CURLINFO_DATA_OUT:
    request.append(data, size);
    break;

  default:
    break;
  }

  return 0;
}

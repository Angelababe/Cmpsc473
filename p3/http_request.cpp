#include <atomic>
#include "utils.h"
#include "log.h"
#include "httpclient.h"
#include "http_request.h"

HttpRequest::~HttpRequest() {}

HttpRequest& HttpRequest::set_body(const std::string& body)
{
  _body = body;
  return *this;
}

HttpRequest& HttpRequest::set_sas_trail(SAS::TrailId trail)
{
  _trail = trail;
  return *this;
}

HttpRequest& HttpRequest::set_allowed_host_state(int allowed_host_state)
{
  _allowed_host_state = allowed_host_state;
  return *this;
}

HttpRequest& HttpRequest::set_username(const std::string& username)
{
  _username = username;
  return *this;
}

HttpRequest& HttpRequest::add_header(const std::string& header)
{
  _headers.push_back(header);
  return *this;
}

HttpResponse HttpRequest::send()
{
  return _client->send_request(*this);
}

HttpResponse::HttpResponse(
                HTTPCode return_code,
                const std::string& body,
                const std::map<std::string, std::string>& headers) :
    _rc(return_code),
    _body(body),
    _headers(headers)
    {}

HttpResponse::~HttpResponse() {}

HTTPCode HttpResponse::get_rc()
{
  return _rc;
}

std::string HttpResponse::get_body()
{
  return _body;
}

std::map<std::string, std::string> HttpResponse::get_headers()
{
  return _headers;
}

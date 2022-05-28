#include <atomic>
#include "httpstack_utils.h"

namespace HttpStackUtils
{
  void PingHandler::process_request(HttpStack::Request& req,
                                    SAS::TrailId trail)
  {
    req.add_content("OK");
    req.set_track_latency(false);
    req.send_reply(200, trail);
  }

  HandlerThreadPool::HandlerThreadPool(unsigned int num_threads,
                                       ExceptionHandler* exception_handler,
                                       unsigned int max_queue) :
    _pool(num_threads,
          exception_handler,
          &exception_callback,
          max_queue),
    _wrappers()
  {
    _pool.start();
  }

  HttpStack::HandlerInterface*
    HandlerThreadPool::wrap(HttpStack::HandlerInterface* handler)
  {
    Wrapper* wrapper = new Wrapper(&_pool, handler);
    _wrappers.push_back(wrapper);
    return wrapper;
  }

  HandlerThreadPool::~HandlerThreadPool()
  {
    for(std::vector<Wrapper*>::iterator it = _wrappers.begin();
        it != _wrappers.end();
        ++it)
    {
      delete *it;
    }

    _wrappers.clear();

    _pool.stop();
    _pool.join();
  }

  HandlerThreadPool::Pool::Pool(unsigned int num_threads,
                                ExceptionHandler* exception_handler,
                                void (*callback)(HttpStackUtils::HandlerThreadPool::RequestParams*),
                                unsigned int max_queue) :
    ThreadPool<RequestParams*>(num_threads, exception_handler, callback, max_queue)
  {}

  void HandlerThreadPool::Pool::
    process_work(HttpStackUtils::HandlerThreadPool::RequestParams*& params)
  {
    params->handler->process_request(params->request, params->trail);
    delete params; params = NULL;
  }

  HandlerThreadPool::Wrapper::Wrapper(Pool* pool,
                                      HandlerInterface* handler) :
    _pool(pool), _handler(handler)
  {}

  void HandlerThreadPool::Wrapper::process_request(HttpStack::Request& req,
                                                   SAS::TrailId trail)
  {
    HandlerThreadPool::RequestParams* params =
      new HandlerThreadPool::RequestParams(_handler, req, trail);
    _pool->add_work(params);
  }

  HttpStack::SasLogger*
    HandlerThreadPool::Wrapper::sas_logger(HttpStack::Request& req)
  {
    return _handler->sas_logger(req);
  }

  ChronosSasLogger CHRONOS_SAS_LOGGER;

  void ChronosSasLogger::sas_log_rx_http_req(SAS::TrailId trail,
                                             HttpStack::Request& req,
                                             uint32_t instance_id)
  {
    log_correlators(trail, req, instance_id);
    log_req_event(trail, req, instance_id, SASEvent::HttpLogLevel::DETAIL);
  }

  // Log a response to chronos.
  void ChronosSasLogger::sas_log_tx_http_rsp(SAS::TrailId trail,
                                             HttpStack::Request& req,
                                             int rc,
                                             uint32_t instance_id)
  {
    log_rsp_event(trail, req, rc, instance_id, SASEvent::HttpLogLevel::DETAIL);
  }

  // Log when a chronos request is rejected due to overload.
  void ChronosSasLogger::sas_log_overload(SAS::TrailId trail,
                                          HttpStack::Request& req,
                                          int rc,
                                          int target_latency,
                                          int current_latency,
                                          float rate_limit,
                                          uint32_t instance_id)
  {
    log_overload_event(trail,
                       req,
                       rc,
                       target_latency,
                       current_latency,
                       rate_limit,
                       instance_id,
                       SASEvent::HttpLogLevel::DETAIL);
  }

}

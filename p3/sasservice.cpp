#include <atomic>
#include <sys/stat.h>
#include <fstream>
#include <stdlib.h>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"

#include "cpp_common_pd_definitions.h"
#include "json_parse_utils.h"
#include "namespace_hop.h"
#include "sasevent.h"
#include "log.h"
#include "saslogger.h"
#include "sasservice.h"


SasService::SasService(std::string system_name, std::string system_type, bool sas_signaling_if, std::string configuration) :
  _configuration(configuration),
  _sas_servers("[]"),
  _single_sas_server("0.0.0.0")
{
  extract_config();

  SAS::init(system_name,
            system_type,
            SASEvent::CURRENT_RESOURCE_BUNDLE,
            get_single_sas_server(),
            sas_write,
            sas_signaling_if ? create_connection_in_signaling_namespace
                             : create_connection_in_management_namespace);
}

void SasService::extract_config()
{
  struct stat s;
  TRC_DEBUG("stat(%s) returns %d", _configuration.c_str(), stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No SAS configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SAS_FILE_MISSING.log();
    return;
  }

  TRC_STATUS("Loading SAS configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string sas_str((std::istreambuf_iterator<char>(fs)),
                       std::istreambuf_iterator<char>());

  if (sas_str == "")
  {
    TRC_ERROR("Failed to read SAS configuration data from %s",
              _configuration.c_str());
    CL_SAS_FILE_EMPTY.log();
    return;
  }

  // Now parse the document
  rapidjson::Document doc;
  doc.Parse<0>(sas_str.c_str());

  if (doc.HasParseError())
  {
    TRC_ERROR("Failed to read SAS configuration data: %s\nError: %s",
              sas_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_SAS_FILE_INVALID.log();
    return;
  }

  try
  {
    JSON_ASSERT_CONTAINS(doc, "sas_servers");
    JSON_ASSERT_ARRAY(doc["sas_servers"]);
    rapidjson::Value& sas_servers = doc["sas_servers"];

    for (rapidjson::Value::ValueIterator sas_it = sas_servers.Begin();
         sas_it != sas_servers.End();
         ++sas_it)
    {
      JSON_ASSERT_OBJECT(*sas_it);
      JSON_ASSERT_CONTAINS(*sas_it, "ip");
      JSON_ASSERT_STRING((*sas_it)["ip"]);

      boost::lock_guard<boost::shared_mutex> write_lock(_sas_server_lock);
      _single_sas_server = (*sas_it)["ip"].GetString();
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    sas_servers.Accept(writer);

    TRC_DEBUG("New _sas_servers config:  %s", buffer.GetString());

    boost::lock_guard<boost::shared_mutex> write_lock(_sas_server_lock);
    _sas_servers = buffer.GetString();
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Badly formed SAS configuration file");
    CL_SAS_FILE_INVALID.log();
  }
}

std::string SasService::get_single_sas_server()
{
  boost::shared_lock<boost::shared_mutex> read_lock(_sas_server_lock);
  return _single_sas_server;
}

std::string SasService::get_sas_servers()
{
  boost::shared_lock<boost::shared_mutex> read_lock(_sas_server_lock);
  return _sas_servers;
}

SasService::~SasService()
{
  SAS::term();
}

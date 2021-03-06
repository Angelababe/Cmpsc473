#include <atomic>
#include <fstream>
#include "log.h"
#include "utils.h"
#include "memcached_config.h"

static const int DEFAULT_TOMBSTONE_LIFETIME = 30 * 60;

MemcachedConfig::MemcachedConfig() :
  servers(), new_servers(), tombstone_lifetime(DEFAULT_TOMBSTONE_LIFETIME)
{}


MemcachedConfigFileReader::MemcachedConfigFileReader(const std::string& filename) :
  _filename(filename)
{}

MemcachedConfigFileReader::~MemcachedConfigFileReader() {}

bool MemcachedConfigFileReader::read_config(MemcachedConfig& config)
{
  bool seen_servers = false;
  config.servers.clear();
  config.new_servers.clear();
  config.tombstone_lifetime = DEFAULT_TOMBSTONE_LIFETIME;
  config.filename = _filename;

  std::ifstream f(_filename);

  if (f.is_open() && f.good())
  {
    TRC_STATUS("Reloading memcached configuration from '%s'", _filename.c_str());

    while (f.good())
    {
      std::string line;
      getline(f, line);
      line = Utils::strip_whitespace(line);

      TRC_DEBUG("Got line: %s", line.c_str());

      if ((line.length() > 0) && (line[0] != '#'))
      {
        // Read a non-blank line.
        std::vector<std::string> tokens;
        Utils::split_string(line, 
                            '=', 
                            tokens, 
                            0, 
                            true);

        std::string key;
        std::string value;
        if (tokens.size() == 1)
        {
          key = tokens[0];
          value = "";
        }
        else if (tokens.size() == 2)
        {
          key = tokens[0];
          value = tokens[1];
        }
        else
        {
          TRC_ERROR("Malformed config file (got bad line: '%s')",
                    line.c_str());
          return false;
        }

        TRC_STATUS(" %s=%s", key.c_str(), value.c_str());

        if (key == "servers")
        {
          Utils::split_string(value, ',', config.servers, 0, true);
          seen_servers = true;
        }
        else if (key == "new_servers")
        {
          Utils::split_string(value, ',', config.new_servers, 0, true);
        }
        else
        {
          TRC_ERROR("Malformed config file (got bad line: '%s')",
                    line.c_str());
          return false;
        }
      }
    }
  }
  else
  {
    TRC_ERROR("Failed to open '%s'", _filename.c_str());
    return false;
  }

  return seen_servers;
}

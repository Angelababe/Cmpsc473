#include <atomic>
#include "utils.h"
#include "log.h"
#include "json_alarms.h"

int main(int argc, char**argv)
{
  std::string json_file;
  std::string process_name;
  int c;

  opterr = 0;
  while ((c = getopt (argc, argv, "j:n:")) != -1)
  {
    switch (c)
      {
      case 'j':
        json_file = optarg;
        break;
      case 'n':
        process_name = optarg;
        break;
      default:
        abort ();
      }
  }
  std::string result;
  std::map<std::string, int> header;

  bool rc = JSONAlarms::validate_alarms_from_json(json_file, result, header);

  if (rc)
  {
    JSONAlarms::write_header_file(process_name, header);  
  }
  else
  { 
    fprintf(stderr, "Invalid JSON file. Error: %s", result.c_str());
  }
}

#include <atomic>
#include <vector>
#include <boost/regex.hpp>
#include "wildcard_utils.h"
#include "utils.h"
#include "log.h"

bool WildcardUtils::is_wildcard_uri(const std::string& possible_wildcard)
{
  std::vector<std::string> wildcard_parts;
  Utils::split_string(possible_wildcard, '@', wildcard_parts, 0, false);
  return (std::count(wildcard_parts[0].begin(),
                     wildcard_parts[0].end(),
                     '!') >= 2);
}

bool WildcardUtils::check_users_equivalent(const std::string& wildcard_user,
                                           const std::string& specific_user)
{
  if (wildcard_user == specific_user)
  {
    return true;
  }
  else if ((wildcard_user == "") || (specific_user == ""))
  {
    return false;
  }
  std::vector<std::string> wildcard_user_parts;
  std::vector<std::string> specific_user_parts;
  Utils::split_string(wildcard_user, ';', wildcard_user_parts, 0, false);
  Utils::split_string(specific_user, ';', specific_user_parts, 0, false);

  if (wildcard_user_parts[0] == specific_user_parts[0])
  {
    return true;
  }
  std::size_t wildcard_start = wildcard_user_parts[0].find_first_of("!");
  std::size_t wildcard_end = wildcard_user_parts[0].find_last_of("!");

  if ((wildcard_start == std::string::npos) ||
      (wildcard_end == std::string::npos) ||
      (wildcard_start == wildcard_end))
  {
    return false;
  }
  std::string wildcard_start_str = wildcard_user_parts[0].substr(0, wildcard_start);
  std::string wildcard_end_str = wildcard_user_parts[0].substr(wildcard_end + 1);
  std::string specific_start_str = specific_user_parts[0].substr(0, wildcard_start);
  std::string specific_end_str = specific_user_parts[0].substr(specific_start_str.size());
  specific_end_str = (specific_end_str.size() >= wildcard_end_str.size()) ?
   specific_end_str.substr(specific_end_str.size() - wildcard_end_str.size()) :
   specific_end_str;

  if ((specific_start_str != wildcard_start_str) ||
      (specific_end_str != wildcard_end_str))
  {
    return false;
  }
  std::string wildcard_part = wildcard_user_parts[0].substr(wildcard_start + 1,
                                                            (wildcard_end -
                                                             wildcard_start -
                                                             1));
  std::string specific_part = specific_user_parts[0].substr(
                                                specific_start_str.size(),
                                                (specific_user_parts[0].size() -
                                                 specific_end_str.size() -
                                                 specific_start_str.size()));
  boost::regex wildcard_regex = boost::regex(wildcard_part,
                                             boost::regex_constants::no_except);

  if ((!wildcard_regex.status()) &&
      (boost::regex_match(specific_part, wildcard_regex)))
  {
    return true;
  }
  else
  {
    return false;
  }
}

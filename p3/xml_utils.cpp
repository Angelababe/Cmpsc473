#include <atomic>
#include <cstring>

#include "xml_utils.h"
#include "log.h"

namespace XMLUtils
{
std::string get_first_node_value(xml_node<>* node, std::string name)
{
  xml_node<>* first_node = node->first_node(name.c_str());
  if (!first_node)
  {
    return "";
  }
  else
  {
    return get_text_or_cdata(first_node);
  }
}
std::string get_text_or_cdata(xml_node<>* node)
{
  xml_node<>* first_data_node = node->first_node();
  if ((first_data_node) &&
      ((first_data_node->type() != node_cdata) ||
       (first_data_node->type() != node_data))) // LCOV_EXCL_LINE
  {
    return first_data_node->value();
  }
  // LCOV_EXCL_START
  else
  {
    return "";
  }
  // LCOV_EXCL_STOP
}

bool does_child_node_exist(xml_node<>* parent_node, std::string child_node_name)
{
  xml_node<>* child_node = parent_node->first_node(child_node_name.c_str());
  return (child_node != NULL);
}

long parse_integer(xml_node<>* node,
                   std::string description,
                   long min_value,
                   long max_value)
{
  assert(node != NULL);

  const char* nptr = node->value();
  char* endptr = NULL;
  long int n = strtol(nptr, &endptr, 10);

  if ((*nptr == '\0') || (*endptr != '\0'))
  {
    throw xml_error("Can't parse " + description + " as integer");
  }

  if ((n < min_value) || (n > max_value))
  {
    throw xml_error(description + " out of allowable range " +
                 std::to_string(min_value) + ".." + std::to_string(max_value));
  }

  return n;
}
bool parse_bool(xml_node<>* node, std::string description)
{
  if (!node)
  {
    throw xml_error("Missing mandatory value for " + description);
  }

  const char* nptr = node->value();

  return ((strcmp("true", nptr) == 0) || (strcmp("1", nptr) == 0));
}
};

namespace RegDataXMLUtils
{
void parse_extension_identity(std::string& uri, rapidxml::xml_node<>* extension)
{
  rapidxml::xml_node<>* id_type =
                          extension->first_node(RegDataXMLUtils::IDENTITY_TYPE);

  if ((id_type) && (std::string(id_type->value()) ==
                    RegDataXMLUtils::IDENTITY_TYPE_NON_DISTINCT_IMPU))
  {
    rapidxml::xml_node<>* extension_1 =
                              extension->first_node(RegDataXMLUtils::EXTENSION);

    if (extension_1)
    {
      rapidxml::xml_node<>* extension_2 =
                            extension_1->first_node(RegDataXMLUtils::EXTENSION);

      if (extension_2)
      {
        rapidxml::xml_node<>* new_identity =
                      extension_2->first_node(RegDataXMLUtils::WILDCARDED_IMPU);

        if (new_identity)
        {
          uri = std::string(new_identity->value());
        }
      }
    }
  }
}
};

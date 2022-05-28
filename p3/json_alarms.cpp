#include <atomic>
#include "json_alarms.h"
#include <algorithm>

namespace JSONAlarms
{
  bool validate_alarms_from_json(std::string path,
                                 std::string& error,
                                 std::map<std::string, int>& header)
  {
    std::vector<AlarmDef::AlarmDefinition> unused;
    return validate_alarms_from_json(path, error, unused, header);
  }

  bool validate_alarms_from_json(std::string path,
                                 std::string& error,
                                 std::vector<AlarmDef::AlarmDefinition>& alarms)
  {
    std::map<std::string, int> unused;
    return validate_alarms_from_json(path, error, alarms, unused);
  }

  bool validate_alarms_from_json(std::string path,
                                 std::string& error,
                                 std::vector<AlarmDef::AlarmDefinition>& alarms,
                                 std::map<std::string, int>& header)
  {
    std::ifstream fs(path.c_str());
    std::string alarms_str((std::istreambuf_iterator<char>(fs)),
                            std::istreambuf_iterator<char>());

    if (alarms_str == "")
    {
      error = "Empty/unopenable file";
      return false;
    }

    rapidjson::Document doc;
    doc.Parse<0>(alarms_str.c_str());

    if (doc.HasParseError())
    {
      error = std::string("Invalid JSON file. Error: ").
                append(rapidjson::GetParseError_En(doc.GetParseError()));
      return false;
    }

    try
    {
      JSON_ASSERT_CONTAINS(doc, "alarms");
      JSON_ASSERT_ARRAY(doc["alarms"]);
      const rapidjson::Value& alarms_arr = doc["alarms"];

      for (rapidjson::Value::ConstValueIterator alarms_it = alarms_arr.Begin();
           alarms_it != alarms_arr.End();
           ++alarms_it)
      {
        int index;
        std::string cause;
        std::string name;

        JSON_GET_INT_MEMBER(*alarms_it, "index", index);
        JSON_GET_STRING_MEMBER(*alarms_it, "cause", cause);
        AlarmDef::Cause e_cause = AlarmDef::cause_to_enum(cause);
        if (e_cause == AlarmDef::UNDEFINED_CAUSE)
        {
          char error_text[100];
          sprintf(error_text, "alarm %d: Invalid cause %s", index, cause.c_str());
          error = std::string(error_text);
          return false;
        }

        JSON_GET_STRING_MEMBER(*alarms_it, "name", name);
        header[name] = index;

        JSON_ASSERT_CONTAINS(*alarms_it, "levels");
        JSON_ASSERT_ARRAY((*alarms_it)["levels"]);
        const rapidjson::Value& alarms_def_arr = (*alarms_it)["levels"];

        std::vector<AlarmDef::SeverityDetails> severity_vec;
        bool found_cleared = false;
        bool found_non_cleared = false;

        for (rapidjson::Value::ConstValueIterator alarms_def_it = alarms_def_arr.Begin();
             alarms_def_it != alarms_def_arr.End();
             ++alarms_def_it)
        {
          std::string severity;
          std::string details;
          std::string description;
          std::string detailed_cause;
          std::string effect;
          std::string action;
          std::string extended_details;
          std::string extended_description;

          JSON_GET_STRING_MEMBER(*alarms_def_it, "severity", severity);
          AlarmDef::Severity e_severity = AlarmDef::severity_to_enum(severity);
          if (e_severity == AlarmDef::UNDEFINED_SEVERITY)
          {
            char error_text[100];
            sprintf(error_text, "alarm %d: Invalid severity %s", index, severity.c_str());
            error = std::string(error_text);
            return false;
          }
          else if (e_severity == AlarmDef::CLEARED)
          {
            found_cleared = true;
          }
          else
          {
            found_non_cleared = true;
          }

          JSON_GET_STRING_MEMBER(*alarms_def_it, "details", details);
          if (details.length() > 255)
          {
            error = exceeded_character_limit_error("details", 255, index);
            return false;
          }
          if (alarms_def_it->HasMember("extended_details"))
          {
            JSON_GET_STRING_MEMBER(*alarms_def_it, "extended_details", extended_details);
            if (extended_details.length() > 4096)
            {
              error = exceeded_character_limit_error("extended_details", 4096, index);
              return false;
            }
          }
          else
          {
            extended_details = details;
          }

          JSON_GET_STRING_MEMBER(*alarms_def_it, "description", description);
          if (description.length() > 255)
          {
            error = exceeded_character_limit_error("description", 255, index);
            return false;
          }
          
          if (alarms_def_it->HasMember("extended_description"))
          {
            JSON_GET_STRING_MEMBER(*alarms_def_it, "extended_description", extended_description);
            if (extended_description.length() > 4096)
            {
              error = exceeded_character_limit_error("extended_description", 4096, index);
              return false;
            }
          }
          else
          {
            extended_description = description;
          }

          JSON_GET_STRING_MEMBER(*alarms_def_it, "cause", detailed_cause);
          if (detailed_cause.length() > 4096)
          {
            error = exceeded_character_limit_error("cause", 4096, index);
            return false;
          }

          JSON_GET_STRING_MEMBER(*alarms_def_it, "effect", effect);
          if (effect.length() > 4096)
          {
            error = exceeded_character_limit_error("effect", 4096, index);
            return false;
          }

          JSON_GET_STRING_MEMBER(*alarms_def_it, "action", action);
          if (action.length() > 4096)
          {
            error = exceeded_character_limit_error("action", 4096, index);
            return false;
          }

          AlarmDef::SeverityDetails sd(e_severity,
                                       description,
                                       details,
                                       detailed_cause,
                                       effect,
                                       action,
                                       extended_details,
                                       extended_description);
          severity_vec.push_back(sd);
        }
      
        if (!found_cleared)
        {
          char error_text[100];
          sprintf(error_text, "alarm %d.*: must define a CLEARED severity", index);
          error = std::string(error_text);
          return false;
        }
        else if (!found_non_cleared)
        {
          char error_text[100];
          sprintf(error_text, "alarm %d.*: must define at least one non-CLEARED severity", index);
          error = std::string(error_text);
          return false;
        }
        else 
        {
          AlarmDef::AlarmDefinition ad = {name,
                                          index,
                                          e_cause,
                                          severity_vec};
          alarms.push_back(ad);
        }
      }
    }
    catch (JsonFormatError err)
    {
      error = std::string("Invalid JSON file: ").append(err._file).
                                                 append(", line: ").
                                                 append(std::to_string(err._line));
      return false;
    }

    return true;
  }

  std::string exceeded_character_limit_error(std::string field, int max_length, int index)
  {
    char error_text[100];
    sprintf(error_text, "alarm %d: '%s' exceeds %d char limit", index, field.c_str(), max_length);
    return std::string(error_text);
  }

  void write_header_file(std::string name, std::map<std::string, int> alarms)
  {
    std::string alarm_values;

    for(std::map<std::string, int>::const_iterator key_it = alarms.begin();
        key_it != alarms.end();
        ++key_it)
    {
      alarm_values.append("static const int ").
                   append(key_it->first).
                   append(" = ").
                   append(std::to_string(key_it->second)).
                   append(";\n");
    }

    std::string alarms_header = "#ifndef " + name + "_alarm_definition_h\n" \
                                "#define " + name + "_alarm_definition_h\n" \
                                "namespace AlarmDef {\n" \
                                + alarm_values + \
                                "}\n#endif";

    std::string filename = name + "_alarmdefinition.h";
    
    std::ofstream file(filename);
    file << alarms_header;
  }
};

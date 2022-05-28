#include <atomic>
#include <string>
#include <algorithm>
#include <memory>
#include "snmp_infinite_base_table.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_row.h"

#include "log.h"
#include "logger.h"

namespace SNMP
{
InfiniteBaseTable::InfiniteBaseTable(std::string name,
                                     std::string tbl_oid,
                                     uint32_t max_row,
                                     uint32_t max_column):
  _name(name),
  _tbl_oid_len(SCRATCH_BUF_LEN),
  _max_row(max_row),
  _max_column(max_column),
  _handler_reg(NULL)
{
  read_objid(tbl_oid.c_str(), _tbl_oid, &_tbl_oid_len);
  ROOT_OID_LEN = std::count(tbl_oid.begin(), tbl_oid.end(), '.');

  TRC_INFO("Registering SNMP table %s", _name.c_str());
  _handler_reg = netsnmp_create_handler_registration(_name.c_str(),
                                                     InfiniteBaseTable::static_netsnmp_table_handler_fn,
                                                     _tbl_oid,
                                                     _tbl_oid_len,
                                                     HANDLER_CAN_RONLY | HANDLER_CAN_GETBULK);
  _handler_reg->handler->myvoid = this;

  netsnmp_register_handler(_handler_reg);
}

InfiniteBaseTable::~InfiniteBaseTable()
{
  if (_handler_reg)
  {
    netsnmp_unregister_handler(_handler_reg);
  }
}
int InfiniteBaseTable::static_netsnmp_table_handler_fn(netsnmp_mib_handler *handler,
                                                       netsnmp_handler_registration *reginfo,
                                                       netsnmp_agent_request_info *reqinfo,
                                                       netsnmp_request_info *requests)
{
  return (static_cast<InfiniteBaseTable*>(handler->myvoid))->InfiniteBaseTable::netsnmp_table_handler_fn(handler,
                                                                                                         reginfo,
                                                                                                         reqinfo,
                                                                                                         requests);
}

int InfiniteBaseTable::netsnmp_table_handler_fn(netsnmp_mib_handler *handler,
                                                netsnmp_handler_registration *reginfo,
                                                netsnmp_agent_request_info *reqinfo,
                                                netsnmp_request_info *requests)
{
  TRC_DEBUG("Starting handling batch of SNMP requests");

  char buf[SCRATCH_BUF_LEN];

  for (; requests != NULL; requests = requests->next)
  {
    try
    {
      oid* req_oid = requests->requestvb->name;
      unsigned long req_oid_len = requests->requestvb->name_length;
      int request_type = reqinfo->mode;

      snprint_objid(buf, sizeof(buf), req_oid, req_oid_len);
      TRC_DEBUG("Handling SNMP %s for OID %s",
                request_type == MODE_GET ? "GET" : "GET_NEXT",
                buf);

      if (requests->processed)
      {
        continue;
      }

      if ((snmp_oid_compare(req_oid, req_oid_len, _tbl_oid, _tbl_oid_len) < 0) &&
          (request_type == MODE_GETNEXT))
      {
        TRC_DEBUG("OID precedes table and mode is GETNEXT - move to start of table");
        req_oid = _tbl_oid;
        req_oid_len = _tbl_oid_len;
      }

      netsnmp_variable_list* var = requests->requestvb;

      Value result = Value::uint(0);

      struct timespec now;
      clock_gettime(CLOCK_REALTIME_COARSE, &now);

      std::unique_ptr<oid[]> fixed_oid(nullptr);
      uint32_t fixed_oid_len = 0;
      if (request_type == MODE_GET)
      {
        fixed_oid_len = req_oid_len;
        fixed_oid = std::unique_ptr<oid[]>(new oid[fixed_oid_len]);
        memcpy(fixed_oid.get(), req_oid, fixed_oid_len * sizeof(oid));

        if (!validate_oid(fixed_oid.get(), fixed_oid_len))
        {
          TRC_DEBUG("Invalid OID for GET request");
          return SNMP_ERR_NOSUCHNAME;
        }
      }
      else if (request_type == MODE_GETNEXT)
      {
        find_next_oid(req_oid,
                      req_oid_len,
                      fixed_oid,
                      fixed_oid_len);

        if (!validate_oid(fixed_oid.get(), fixed_oid_len))
        {
          TRC_DEBUG("This request goes beyond the table");

          snmp_set_var_objid(var,
                             fixed_oid.get(),
                             fixed_oid_len);

          snmp_set_var_typed_value(var,
                                   result.type,
                                   result.value,
                                   result.size);

          return SNMP_ERR_NOERROR;
        }
      }

      std::string tag;
      uint32_t row;
      uint32_t column;
      parse_oid(fixed_oid.get(), fixed_oid_len, tag, row, column);

      snprint_objid(buf, sizeof(buf), fixed_oid.get(), fixed_oid_len);
      TRC_DEBUG("Parsed SNMP request to OID %s with tag %s and cell (%d, %d)",
                buf, tag.c_str(), row, column);

      result = get_value(tag, column, row, now);

      snmp_set_var_objid(var,
                         fixed_oid.get(),
                         fixed_oid_len);

      snmp_set_var_typed_value(var,
                               result.type,
                               result.value,
                               result.size);
    }
    catch (std::exception& e)
    {
      TRC_ERROR("Exception while handling SNMP request: %s", e.what());
      return SNMP_ERR_GENERR;
    }
  }

  TRC_DEBUG("Finished handling batch of SNMP requests");

  return SNMP_ERR_NOERROR;
}
bool InfiniteBaseTable::validate_oid(const oid* oid,
                                     const uint32_t oid_len)
{
  if (netsnmp_oid_equals(oid, ROOT_OID_LEN, _tbl_oid, ROOT_OID_LEN) != 0)
  {
    TRC_DEBUG("Requested OID is not under the table's root");
    return false;
  }

  if (oid_len < ROOT_OID_LEN + 1)
  {
    TRC_DEBUG("Not enough room for the ROOT and the length field");
    return false;
  }

  uint32_t tag_len = oid[ROOT_OID_LEN];

  if (oid_len != ROOT_OID_LEN + 1 + tag_len + 2)
  {
    TRC_DEBUG("Requested OID is not the right size to be a valid cell in the table");
    return false;
  }

  for (uint32_t ii = 0; ii < tag_len; ++ii)
  {
    if ((oid[ROOT_OID_LEN + 1 + ii] < 'A') ||
        (oid[ROOT_OID_LEN + 1 + ii] > 'Z'))
    {
      TRC_DEBUG("Requested tag contains invalid characters");
      return false;
    }
  }

  if ((oid[ROOT_OID_LEN + 1 + tag_len] > _max_column) ||
      (oid[ROOT_OID_LEN + 1 + tag_len + 1] > _max_row))
  {
    TRC_DEBUG("Requested row/column are out of bounds");
    return false;
  }

  return true;
}

void InfiniteBaseTable::parse_oid(const oid* oid,
                                  const uint32_t oid_len,
                                  std::string& tag,
                                  uint32_t& row,
                                  uint32_t& column)
{
  if (oid_len < ROOT_OID_LEN + 1)
  {
    throw std::invalid_argument("OID is too short to hold table root and tag length");
  }

  uint32_t length_of_tag = oid[ROOT_OID_LEN];

  if (oid_len != ROOT_OID_LEN + 1 + length_of_tag + 2)
  {
    throw std::invalid_argument("OID is invalid length");
  }

  tag.reserve(length_of_tag);

  for (unsigned int ii = 0; ii < length_of_tag; ++ii)
  {
    if ((oid[ROOT_OID_LEN + 1 + ii] < 'A') ||
        (oid[ROOT_OID_LEN + 1 + ii] > 'Z'))
    {
      throw std::invalid_argument("OID tag contains invalid character");
    }

    tag.push_back((char)oid[ROOT_OID_LEN + 1 + ii]);
  }

  column = oid[ROOT_OID_LEN + 1 + length_of_tag];
  row = oid[ROOT_OID_LEN + 1 + length_of_tag + 1];
}
void InfiniteBaseTable::find_next_oid(const oid* req_oid,
                                      const uint32_t& req_oid_len,
                                      std::unique_ptr<oid[]>& new_oid,
                                      uint32_t& new_oid_len)
{
  uint32_t tmp_oid_len = req_oid_len;
  std::unique_ptr<oid[]> tmp_oid(new oid[tmp_oid_len]);
  memcpy(tmp_oid.get(), req_oid, tmp_oid_len * sizeof(oid));

  while (true)
  {
    char tmp_buf[SCRATCH_BUF_LEN];
    snprint_objid(tmp_buf, sizeof(tmp_buf), tmp_oid.get(), tmp_oid_len);
    TRC_DEBUG("Finding OID after %s", tmp_buf);

    if ((tmp_oid_len < ROOT_OID_LEN + 1) ||
        (tmp_oid[ROOT_OID_LEN] == 0))
    {
      TRC_DEBUG("Tag length not provided (or 0), skip the table");
      new_oid_len = ROOT_OID_LEN;
      new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
      memcpy(new_oid.get(), _tbl_oid, ROOT_OID_LEN * sizeof(oid));
      new_oid[ROOT_OID_LEN - 1]++;
      break;
    }

    if (tmp_oid[ROOT_OID_LEN] > MAX_TAG_LEN)
    {
      TRC_DEBUG("Tag length is too high, leaving table");
      new_oid_len = ROOT_OID_LEN;
      new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
      memcpy(new_oid.get(), _tbl_oid, ROOT_OID_LEN * sizeof(oid));
      new_oid[ROOT_OID_LEN - 1]++;
      break;
    }

    uint32_t tag_len = tmp_oid[ROOT_OID_LEN];
    bool backtracking = false;
    bool finished = false;
    for (uint32_t ii = 0;
         (ii < tag_len) && (ii < tmp_oid_len - ROOT_OID_LEN - 1);
         ++ii)
    {
      if (tmp_oid[ROOT_OID_LEN + 1 + ii] > 'Z')
      {
        if (ii != 0)
        {
          TRC_DEBUG("Tag contains character after Z, backtracking after incrementing previous character");
        }
        else
        {
          TRC_DEBUG("Tag starts after 'Z', backtracking with longer tag");
        }
        tmp_oid_len = ROOT_OID_LEN + 1 + ii;
        tmp_oid[tmp_oid_len - 1]++;
        backtracking = true;
        break;
      }
      else if (tmp_oid[ROOT_OID_LEN + 1 + ii] < 'A')
      {
        TRC_DEBUG("Tag contains character before 'A', filling tag with 'A's");
        new_oid_len = ROOT_OID_LEN + 1 + tag_len + 2;
        new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
        memcpy(new_oid.get(), tmp_oid.get(), (ROOT_OID_LEN + 1 + ii) * sizeof(oid));
        for (; ii < tag_len; ++ii)
        {
          new_oid[ROOT_OID_LEN + 1 + ii] = 'A';     
        new_oid[ROOT_OID_LEN + 1 + tag_len] = 2;    
        new_oid[ROOT_OID_LEN + 1 + tag_len + 1] = 1;
        finished = true;
        break;
      }
    }
    if (backtracking) { continue; }
    if (finished) { break; }

   
    if (tmp_oid_len < ROOT_OID_LEN + 1 + tag_len)
    {
      TRC_DEBUG("Tag incomplete, filling with 'A's");
      new_oid_len = ROOT_OID_LEN + 1 + tag_len + 2;
      new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
      memcpy(new_oid.get(), tmp_oid.get(), tmp_oid_len * sizeof(oid));
      for (uint32_t ii = tmp_oid_len; ii < ROOT_OID_LEN + 1 + tag_len; ++ii)
      {
        new_oid[ii] = 'A';      // Fill out the tag
      }
      new_oid[ROOT_OID_LEN + 1 + tag_len] = 2;     // Column
      new_oid[ROOT_OID_LEN + 1 + tag_len + 1] = 1; // Row
      break;
    }

    if (tmp_oid_len < ROOT_OID_LEN + 1 + tag_len + 1)
    {
      TRC_DEBUG("No column provided, assuming first non-index one");
      new_oid_len = ROOT_OID_LEN + 1 + tag_len + 2;
      new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
      memcpy(new_oid.get(), tmp_oid.get(), tmp_oid_len * sizeof(oid));
      new_oid[ROOT_OID_LEN + 1 + tag_len] = 2;     // Column
      new_oid[ROOT_OID_LEN + 1 + tag_len + 1] = 1; // Row
      break;
    }

    if (tmp_oid[ROOT_OID_LEN + 1 + tag_len] > _max_column)
    {
      TRC_DEBUG("Column too high, backtracking with incremented tag");
      tmp_oid_len = ROOT_OID_LEN + 1 + tag_len;
      tmp_oid[tmp_oid_len - 1]++;
      continue;
    }

    // Check if the request provided a row.
    if (tmp_oid_len < ROOT_OID_LEN + 1 + tag_len + 2)
    {
      TRC_DEBUG("No row provided, assuming first one");
      new_oid_len = ROOT_OID_LEN + 1 + tag_len + 2;
      new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
      memcpy(new_oid.get(), tmp_oid.get(), tmp_oid_len * sizeof(oid));
      new_oid[ROOT_OID_LEN + 1 + tag_len + 1] = 1; // Row
      break;
    }

    if (tmp_oid[ROOT_OID_LEN + 1 + tag_len + 1] > _max_row - 1)
    {
      TRC_DEBUG("Row too high, backtracking with incremented column");
      tmp_oid_len = ROOT_OID_LEN + 1 + tag_len + 1;
      tmp_oid[tmp_oid_len - 1]++;
      continue;
    }

    TRC_DEBUG("Incrementing row to find next OID");
    new_oid_len = ROOT_OID_LEN + 1 + tag_len + 2;
    new_oid = std::unique_ptr<oid[]>(new oid[new_oid_len]);
    memcpy(new_oid.get(), tmp_oid.get(), (ROOT_OID_LEN + 1 + tag_len + 1) * sizeof(oid));
    new_oid[ROOT_OID_LEN + 1 + tag_len + 1] = tmp_oid[ROOT_OID_LEN + 1 + tag_len + 1] + 1;
    break;
  }

  char buf[SCRATCH_BUF_LEN];
  char buf2[SCRATCH_BUF_LEN];
  snprint_objid(buf, sizeof(buf), req_oid, req_oid_len);
  snprint_objid(buf2, sizeof(buf2), new_oid.get(), new_oid_len);
  TRC_DEBUG("Found next OID, %s -> %s", buf, buf2);
  return;
}
}

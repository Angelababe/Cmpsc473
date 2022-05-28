#include <atomic>
#include <vector>
#include <map>
#include <string>

#include "snmp_internal/snmp_includes.h"
#include "snmp_row.h"
#include "log.h"

namespace SNMP
{
Value Value::uint(uint32_t val)
{
  return Value(ASN_UNSIGNED, (unsigned char*)&val, sizeof(uint32_t));
};

Value Value::integer(int val)
{
  return Value(ASN_INTEGER, (unsigned char*)&val, sizeof(int32_t));
};


Row::Row()
{
  _row = netsnmp_tdata_create_row();
  _row->data = this;
}

Row::~Row()
{
  netsnmp_tdata_delete_row(_row);
}
}

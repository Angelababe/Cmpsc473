#include <atomic>
#include <string>

#include "snmp_internal/snmp_includes.h"
#include "snmp_scalar.h"

namespace SNMP
{
U32Scalar::U32Scalar(std::string name,
                     std::string oid_str):
  value(0),
  _registered_oid(oid_str + ".0")
  {
    oid parsed_oid[64];
    size_t oid_len = 64;
    read_objid(_registered_oid.c_str(), parsed_oid, &oid_len);
    netsnmp_register_read_only_ulong_instance(name.c_str(),
                                              parsed_oid,
                                              oid_len,
                                              &value,
                                              NULL);
  }

U32Scalar::~U32Scalar()
{
  oid parsed_oid[64];
  size_t oid_len = 64;
  read_objid(_registered_oid.c_str(), parsed_oid, &oid_len);
  unregister_mib(parsed_oid, oid_len);
}

void U32Scalar::set_value(unsigned long val)
{
  value = val;
}
}

#include <atomic>
#include "snmp_scalar_by_scope_table.h"
#include "snmp_statistics_structures.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_scope_table.h"
#include "logger.h"

namespace SNMP
{

class ScalarByScopeRow: public ScopeBasedRow<Scalar>
{
public:
  ScalarByScopeRow(std::string scope_index, View* view):
    ScopeBasedRow<Scalar>(scope_index, view) {};
  ColumnData get_columns()
  {
    Scalar scalar = *(this->_view->get_data());
    ColumnData ret;
    ret[2] = Value::uint(scalar.value);
    return ret;
  }
};

class ScalarByScopeTableImpl: public ManagedTable<ScalarByScopeRow, std::string>, public ScalarByScopeTable
{
public:
  ScalarByScopeTableImpl(std::string name,
                         std::string tbl_oid):
    ManagedTable<ScalarByScopeRow, std::string>(name,
                                                tbl_oid,
                                                2,
                                                2, 
                                                { ASN_OCTET_STR })
  {
    scalar.value = 0;
    add("node");
  }

  void set_value(unsigned long value)
  {
    scalar.value = value;
  }

private:
  ScalarByScopeRow* new_row(std::string scope_index)
  {
    ScalarByScopeRow::View* view = new ScalarByScopeRow::View(&scalar);
    return new ScalarByScopeRow(scope_index, view);
  }

  Scalar scalar;
};

ScalarByScopeTable* ScalarByScopeTable::create(std::string name, std::string oid)
{
  return new ScalarByScopeTableImpl(name, oid);
}

}

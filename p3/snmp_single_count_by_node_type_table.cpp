#include <atomic>
#include "snmp_single_count_by_node_type_table.h"
#include "snmp_statistics_structures.h"
#include "snmp_internal/snmp_includes.h"
#include "snmp_internal/snmp_counts_by_other_type_table.h"
#include "snmp_node_types.h"
#include "logger.h"

namespace SNMP
{

class SingleCountByNodeTypeRow: public TimeAndOtherTypeBasedRow<SingleCount>
{
public:
  SingleCountByNodeTypeRow(int time_index, int type_index, View* view):
    TimeAndOtherTypeBasedRow<SingleCount>(time_index, type_index, view) {};
  ColumnData get_columns()
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME_COARSE, &now);

    SingleCount accumulated = *(this->_view->get_data(now));

    ColumnData ret;
    ret[1] = Value::integer(this->_index);
    ret[2] = Value::integer(this->_type_index);
    ret[3] = Value::uint(accumulated.count);
    return ret;
  }

  static int get_count_size() { return 1; }
};

class SingleCountByNodeTypeTableImpl: public CountsByOtherTypeTableImpl<SingleCountByNodeTypeRow, SingleCount>, public SingleCountByNodeTypeTable
{
public:
  SingleCountByNodeTypeTableImpl(std::string name,
                                 std::string tbl_oid,
                                 std::vector<int> node_types): CountsByOtherTypeTableImpl<SingleCountByNodeTypeRow, SingleCount>(name, tbl_oid, node_types)
  {}

  void increment(NodeTypes type)
  {
    five_second[type]->get_current()->count++;
    five_minute[type]->get_current()->count++;
  }
};

SingleCountByNodeTypeTable* SingleCountByNodeTypeTable::create(std::string name,
                                                               std::string oid,
                                                               std::vector<int> node_types)
{
  return new SingleCountByNodeTypeTableImpl(name, oid, node_types);
}

}

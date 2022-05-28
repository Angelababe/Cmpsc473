
#include <atomic>
#include "utils.h"
#include "timer_heap.h"
#include "utils.h"

bool PopsBefore::operator()(HeapableTimer* const& t1, HeapableTimer* const& t2) const
{
  return Utils::overflow_less_than(t2->get_pop_time(), t1->get_pop_time());
}



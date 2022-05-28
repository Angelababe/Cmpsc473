#include <stdio.h>
#include "pointer.h"
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

int tests_run = 0;
#define mu_str_(text) #text
#define mu_str(text) mu_str_(text)
#define mu_assert(message, test) do { if (!(test)) return "FAILURE: See " __FILE__ " Line " mu_str(__LINE__) ": " message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                                if (message) return message; } while (0)

static int string_equal(const char* str1, const char* str2) {
    if ((str1 == NULL) && (str2 == NULL)) {
        return 1;
    }
    if ((str1 == NULL) || (str2 == NULL)) {
        return 0;
    }
    return (strcmp(str1, str2) == 0);
}

static int approx_equal(double val1, double val2) {
    double epsilon = 1e-9;
    return fabs(val1 - val2) < epsilon;
}

char* test_static_price_object()
{
    StaticPriceObject obj;
    static_price_object_construct(&obj, 7, "test_obj1", 1.99);
    mu_assert("test_static_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 7);
    mu_assert("test_static_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj1"));
    mu_assert("test_static_price_object: Testing price is set appropriately",
              approx_equal(static_price(&obj), 1.99));
    static_price_object_construct(&obj, 1, "test_obj2", 0.5);
    mu_assert("test_static_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 1);
    mu_assert("test_static_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj2"));
    mu_assert("test_static_price_object: Testing price is set appropriately",
              approx_equal(static_price(&obj), 0.5));
    static_price_object_construct(&obj, 4, "test_obj3", 2.8);
    mu_assert("test_static_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 4);
    mu_assert("test_static_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj3"));
    mu_assert("test_static_price_object: Testing price is set appropriately",
              approx_equal(static_price(&obj), 2.8));
    static_price_object_construct(&obj, 0, "test_obj4", 3.7);
    mu_assert("test_static_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 0);
    mu_assert("test_static_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj4"));
    mu_assert("test_static_price_object: Testing out of stock price",
              static_price(&obj) == ERR_OUT_OF_STOCK);
    return NULL;
}

char* test_dynamic_price_object()
{
    DynamicPriceObject obj;
    dynamic_price_object_construct(&obj, 7, "test_obj1", 1.99, 0);
    mu_assert("test_dynamic_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 7);
    mu_assert("test_dynamic_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj1"));
    mu_assert("test_dynamic_price_object: Testing price is set appropriately",
              approx_equal(dynamic_price(&obj), 1.99));
    dynamic_price_object_construct(&obj, 1, "test_obj2", 0.5, -2.0);
    mu_assert("test_dynamic_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 1);
    mu_assert("test_dynamic_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj2"));
    mu_assert("test_dynamic_price_object: Testing price is set appropriately",
              approx_equal(dynamic_price(&obj), 0.5));
    dynamic_price_object_construct(&obj, 4, "test_obj3", 2.8, -0.5);
    mu_assert("test_dynamic_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 4);
    mu_assert("test_dynamic_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj3"));
    mu_assert("test_dynamic_price_object: Testing price is set appropriately",
              approx_equal(dynamic_price(&obj), 1.4));
    dynamic_price_object_construct(&obj, 0, "test_obj4", 3.7, 0);
    mu_assert("test_dynamic_price_object: Testing quantity is set appropriately",
              object_quantity((Object*)&obj) == 0);
    mu_assert("test_dynamic_price_object: Testing name is set appropriately",
              string_equal(object_name((Object*)&obj), "test_obj4"));
    mu_assert("test_dynamic_price_object: Testing out of stock price",
              dynamic_price(&obj) == ERR_OUT_OF_STOCK);
    return NULL;
}

char* test_polymorphism()
{
    StaticPriceObject static_obj;
    static_price_object_construct(&static_obj, 7, "test_static_obj", 1.99);
    mu_assert("test_polymorphism: Testing object price is calling the right function",
              object_price((Object*)&static_obj) == static_price(&static_obj));
    mu_assert("test_polymorphism: Testing object bulk price is calling the right function",
              object_bulk_price((Object*)&static_obj, 3) == static_bulk_price(&static_obj, 3));
    DynamicPriceObject dynamic_obj;
    dynamic_price_object_construct(&dynamic_obj, 7, "test_dynamic_obj", 1.99, 0);
    mu_assert("test_polymorphism: Testing object price is calling the right function",
              object_price((Object*)&dynamic_obj) == dynamic_price(&dynamic_obj));
    mu_assert("test_polymorphism: Testing object bulk price is calling the right function",
              object_bulk_price((Object*)&dynamic_obj, 3) == dynamic_bulk_price(&dynamic_obj, 3));
    return NULL;
}

char* test_compare_by_quantity()
{
    StaticPriceObject obj1;
    DynamicPriceObject obj2;
    static_price_object_construct(&obj1, 7, "obj1", 1.99);
    dynamic_price_object_construct(&obj2, 7, "obj2", 1.99, 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj1, (Object*)&obj2) == 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj2, (Object*)&obj1) == 0);
    static_price_object_construct(&obj1, 5, "obj1", 1.99);
    dynamic_price_object_construct(&obj2, 7, "obj2", 1.99, 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj1, (Object*)&obj2) < 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj2, (Object*)&obj1) > 0);
    static_price_object_construct(&obj1, 7, "obj1", 1.99);
    dynamic_price_object_construct(&obj2, 3, "obj2", 1.99, 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj1, (Object*)&obj2) > 0);
    mu_assert("test_compare_by_quantity: Testing object quantity comparison is returning the correct comparison values",
              compare_by_quantity((Object*)&obj2, (Object*)&obj1) < 0);
    return NULL;
}

char* test_compare_by_price()
{
    StaticPriceObject obj1;
    DynamicPriceObject obj2;
    static_price_object_construct(&obj1, 7, "obj1", 1.99);
    dynamic_price_object_construct(&obj2, 7, "obj2", 1.99, 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj1, (Object*)&obj2) == 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj2, (Object*)&obj1) == 0);
    static_price_object_construct(&obj1, 7, "obj1", 1.98);
    dynamic_price_object_construct(&obj2, 7, "obj2", 1.99, 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj1, (Object*)&obj2) < 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj2, (Object*)&obj1) > 0);
    static_price_object_construct(&obj1, 7, "obj1", 1.99);
    dynamic_price_object_construct(&obj2, 7, "obj2", 1.95, 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj1, (Object*)&obj2) > 0);
    mu_assert("test_compare_by_price: Testing object price comparison is returning the correct comparison values",
              compare_by_price((Object*)&obj2, (Object*)&obj1) < 0);
    return NULL;
}

char* test_static_bulk_price()
{
    StaticPriceObject obj;
    static_price_object_construct(&obj, 7, "test_obj", 0.5);
    mu_assert("test_static_bulk_price: Testing base bulk price is calculated appropriately",
              approx_equal(static_bulk_price(&obj, 1), 0.5));
    mu_assert("test_static_bulk_price: Testing zero bulk price is calculated appropriately",
              static_bulk_price(&obj, 0) == 0);
    mu_assert("test_static_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(static_bulk_price(&obj, 2), 0.95));
    mu_assert("test_static_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(static_bulk_price(&obj, 3), 1.4));
    mu_assert("test_static_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(static_bulk_price(&obj, 5), 2.3));
    static_price_object_construct(&obj, 1, "test_obj", 1.99);
    mu_assert("test_static_bulk_price: Testing base bulk price is calculated appropriately",
              approx_equal(static_bulk_price(&obj, 1), 1.99));
    mu_assert("test_static_bulk_price: Testing zero bulk price is calculated appropriately",
              static_bulk_price(&obj, 0) == 0);
    mu_assert("test_static_bulk_price: Testing out of stock bulk price",
              static_bulk_price(&obj, 2) == ERR_OUT_OF_STOCK);
    return NULL;
}

char* test_dynamic_bulk_price()
{
    DynamicPriceObject obj;
    dynamic_price_object_construct(&obj, 7, "test_obj1", 0.5, 0);
    mu_assert("test_dynamic_bulk_price: Testing base bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 1), 0.5));
    mu_assert("test_dynamic_bulk_price: Testing zero bulk price is calculated appropriately",
              dynamic_bulk_price(&obj, 0) == 0);
    mu_assert("test_dynamic_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 2), 0.95));
    mu_assert("test_dynamic_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 3), 1.4));
    mu_assert("test_dynamic_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 5), 2.3));
    dynamic_price_object_construct(&obj, 1, "test_obj2", 1.99, -0.5);
    mu_assert("test_dynamic_bulk_price: Testing base bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 1), 1.99));
    mu_assert("test_dynamic_bulk_price: Testing zero bulk price is calculated appropriately",
              dynamic_bulk_price(&obj, 0) == 0);
    mu_assert("test_dynamic_bulk_price: Testing out of stock bulk price",
              dynamic_bulk_price(&obj, 2) == ERR_OUT_OF_STOCK);
    dynamic_price_object_construct(&obj, 2, "test_obj3", 2.8, -2.0);
    mu_assert("test_dynamic_bulk_price: Testing base bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 1), 0.7));
    mu_assert("test_dynamic_bulk_price: Testing zero bulk price is calculated appropriately",
              dynamic_bulk_price(&obj, 0) == 0);
    mu_assert("test_dynamic_bulk_price: Testing bulk price is calculated appropriately",
              approx_equal(dynamic_bulk_price(&obj, 2), 3.22));
    return NULL;
}

char* test_iterator_basic()
{
    Object obj3;
    Object obj2;
    Object obj1;
    LinkedListNode node3 = {&obj3, NULL};
    LinkedListNode node2 = {&obj2, &node3};
    LinkedListNode node1 = {&obj1, &node2};
    LinkedListNode* head = &node1;
    LinkedListIterator iter;
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_basic: Testing iterator_begin",
              iterator_get_object(&iter) == &obj1);
    mu_assert("test_iterator_basic: Testing iterator_at_end",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next",
              iterator_get_object(&iter) == &obj2);
    mu_assert("test_iterator_basic: Testing iterator_at_end",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next",
              iterator_get_object(&iter) == &obj3);
    mu_assert("test_iterator_basic: Testing iterator_at_end",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_basic: Testing iterator_at_end",
              iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next at end of list",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_basic: Testing iterator_at_end",
              iterator_at_end(&iter));
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_basic: Testing iterator_begin a second time",
              iterator_get_object(&iter) == &obj1);
    mu_assert("test_iterator_basic: Testing iterator_at_end a second time",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next a second time",
              iterator_get_object(&iter) == &obj2);
    mu_assert("test_iterator_basic: Testing iterator_at_end a second time",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next a second time",
              iterator_get_object(&iter) == &obj3);
    mu_assert("test_iterator_basic: Testing iterator_at_end a second time",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next a second time",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_basic: Testing iterator_at_enda second time",
              iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_basic: Testing iterator_next at end of list a second time",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_basic: Testing iterator_at_end a second time",
              iterator_at_end(&iter));
    return NULL;
}

char* test_iterator_remove()
{
    Object obj5;
    Object obj4;
    Object obj3;
    Object obj2;
    Object obj1;
    LinkedListNode node5 = {&obj5, NULL};
    LinkedListNode node4 = {&obj4, &node5};
    LinkedListNode node3 = {&obj3, &node4};
    LinkedListNode node2 = {&obj2, &node3};
    LinkedListNode node1 = {&obj1, &node2};
    LinkedListNode* head = &node1;
    LinkedListIterator iter;
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_remove: Testing iterator_remove first node",
              iterator_remove(&iter) == &node1);
    mu_assert("test_iterator_remove: Testing iterator_remove preserves iterator",
              iterator_get_object(&iter) == &obj2);
    mu_assert("test_iterator_remove: Testing iterator_remove preserves head",
              head == &node2);
    iterator_next(&iter);
    mu_assert("test_iterator_remove: Testing iterator_remove middle node",
              iterator_remove(&iter) == &node3);
    mu_assert("test_iterator_remove: Testing iterator_remove preserves iterator",
              iterator_get_object(&iter) == &obj4);
    iterator_next(&iter);
    mu_assert("test_iterator_remove: Testing iterator_remove last node",
              iterator_remove(&iter) == &node5);
    mu_assert("test_iterator_remove: Testing iterator_remove preserves iterator",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_remove: Testing iterator_at_end",
              iterator_at_end(&iter));
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_remove: Testing iterator_begin after remove",
              iterator_get_object(&iter) == &obj2);
    mu_assert("test_iterator_remove: Testing iterator_at_end after remove",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_remove: Testing iterator_next after remove",
              iterator_get_object(&iter) == &obj4);
    mu_assert("test_iterator_remove: Testing iterator_at_end after remove",
              !iterator_at_end(&iter));
    iterator_next(&iter);
    mu_assert("test_iterator_remove: Testing iterator_next after remove",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_remove: Testing iterator_at_end after remove",
              iterator_at_end(&iter));
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_remove: Testing iterator_remove all nodes",
              iterator_remove(&iter) == &node2);
    mu_assert("test_iterator_remove: Testing iterator_remove all nodes",
              iterator_remove(&iter) == &node4);
    mu_assert("test_iterator_remove: Testing iterator_next after remove all nodes",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_remove: Testing iterator_at_end after remove all nodes",
              iterator_at_end(&iter));
    mu_assert("test_iterator_remove: Testing iterator_remove all nodes preserves head",
              head == NULL);
    return NULL;
}

char* test_iterator_insert()
{
    Object obj8;
    Object obj7;
    Object obj6;
    Object obj5;
    Object obj4;
    Object obj3;
    Object obj2;
    Object obj1;
    LinkedListNode node8 = {&obj8, NULL};
    LinkedListNode node7 = {&obj7, NULL};
    LinkedListNode node6 = {&obj6, NULL};
    LinkedListNode node5 = {&obj5, NULL};
    LinkedListNode node4 = {&obj4, NULL};
    LinkedListNode node3 = {&obj3, NULL};
    LinkedListNode node2 = {&obj2, NULL};
    LinkedListNode node1 = {&obj1, NULL};
    LinkedListNode* head = NULL;
    LinkedListIterator iter;
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_insert: Testing iterator_insert_after empty list",
              iterator_insert_after(&iter, &node4) == ERR_INSERT_AFTER_END);
    mu_assert("test_iterator_insert: Testing iterator_insert_after empty list",
              head == NULL);
    mu_assert("test_iterator_insert: Testing iterator_insert_after empty list",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_insert: Testing iterator_insert_after empty list",
              iterator_at_end(&iter));
    iterator_insert_before(&iter, &node4);
    mu_assert("test_iterator_insert: Testing iterator_insert_before empty list",
              head == &node4);
    mu_assert("test_iterator_insert: Testing iterator_insert_before empty list",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_insert: Testing iterator_insert_before empty list",
              iterator_at_end(&iter));
    mu_assert("test_iterator_insert: Testing iterator_insert_after end of list",
              iterator_insert_after(&iter, &node7) == ERR_INSERT_AFTER_END);
    mu_assert("test_iterator_insert: Testing iterator_insert_after end of list",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_insert: Testing iterator_insert_after end of list",
              iterator_at_end(&iter));
    iterator_insert_before(&iter, &node7);
    mu_assert("test_iterator_insert: Testing iterator_insert_before end of list",
              iterator_get_object(&iter) == NULL);
    mu_assert("test_iterator_insert: Testing iterator_insert_before end of list",
              iterator_at_end(&iter));
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_insert: Testing iterator_insert_before end of list",
              iterator_get_object(&iter) == &obj4);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_before end of list",
              iterator_get_object(&iter) == &obj7);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_before end of list",
              iterator_get_object(&iter) == NULL);
    iterator_begin(&iter, &head);
    iterator_insert_before(&iter, &node1);
    mu_assert("test_iterator_insert: Testing iterator_insert_before beginning of list",
              iterator_get_object(&iter) == &obj4);
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_insert: Testing iterator_insert_before beginning of list",
              iterator_get_object(&iter) == &obj1);
    mu_assert("test_iterator_insert: Testing iterator_insert_after beginning of list",
              iterator_insert_after(&iter, &node2) == 0);
    mu_assert("test_iterator_insert: Testing iterator_insert_after beginning of list",
              iterator_get_object(&iter) == &obj1);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after beginning of list",
              iterator_get_object(&iter) == &obj2);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after beginning of list",
              iterator_get_object(&iter) == &obj4);
    iterator_insert_before(&iter, &node3);
    mu_assert("test_iterator_insert: Testing iterator_insert_before middle of list",
              iterator_get_object(&iter) == &obj4);
    mu_assert("test_iterator_insert: Testing iterator_insert_after middle of list",
              iterator_insert_after(&iter, &node5) == 0);
    mu_assert("test_iterator_insert: Testing iterator_insert_after middle of list",
              iterator_get_object(&iter) == &obj4);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after middle of list",
              iterator_get_object(&iter) == &obj5);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after middle of list",
              iterator_get_object(&iter) == &obj7);
    iterator_insert_before(&iter, &node6);
    mu_assert("test_iterator_insert: Testing iterator_insert_before last node in list",
              iterator_get_object(&iter) == &obj7);
    mu_assert("test_iterator_insert: Testing iterator_insert_after last node in list",
              iterator_insert_after(&iter, &node8) == 0);
    mu_assert("test_iterator_insert: Testing iterator_insert_after last node in list",
              iterator_get_object(&iter) == &obj7);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after last node in list",
              iterator_get_object(&iter) == &obj8);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing iterator_insert_after last node in list",
              iterator_get_object(&iter) == NULL);
    iterator_begin(&iter, &head);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj1);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj2);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj3);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj4);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj5);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj6);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj7);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == &obj8);
    iterator_next(&iter);
    mu_assert("test_iterator_insert: Testing final list",
              iterator_get_object(&iter) == NULL);
    return NULL;
}

char* test_max_min_avg_price()
{
    StaticPriceObject obj3;
    DynamicPriceObject obj2;
    StaticPriceObject obj1;
    LinkedListNode node3 = {&obj3.obj, NULL};
    LinkedListNode node2 = {&obj2.obj, &node3};
    LinkedListNode node1 = {&obj1.obj, &node2};
    LinkedListNode* head = &node1;
    double max = 0;
    double min = 0;
    double avg = 0;
    static_price_object_construct(&obj1, 7, "obj1", 1.5);
    dynamic_price_object_construct(&obj2, 4, "obj2", 7.0, -0.5);
    static_price_object_construct(&obj3, 1, "obj3", 1.0);
    max_min_avg_price(&head, &max, &min, &avg);
    mu_assert("test_max_min_avg_price: Testing max_min_avg_price max is correct",
              approx_equal(max, 3.5));
    mu_assert("test_max_min_avg_price: Testing max_min_avg_price min is correct",
              approx_equal(min, 1.0));
    mu_assert("test_max_min_avg_price: Testing max_min_avg_price avg is correct",
              approx_equal(avg, 2.0));
    return NULL;
}

static Data gather(Object* obj, Data data) {
    double* price = (double*)data.ptr;
    *price = object_price(obj);
    data.ptr = (void*)(price + 1);
    return data;
}

char* test_foreach()
{
    StaticPriceObject obj3;
    DynamicPriceObject obj2;
    StaticPriceObject obj1;
    LinkedListNode node3 = {&obj3.obj, NULL};
    LinkedListNode node2 = {&obj2.obj, &node3};
    LinkedListNode node1 = {&obj1.obj, &node2};
    LinkedListNode* head = &node1;
    double price[3] = {0, 0, 0};
    Data data;
    data.ptr = (void*)price;
    static_price_object_construct(&obj1, 7, "obj1", 1.5);
    dynamic_price_object_construct(&obj2, 4, "obj2", 7.0, -0.5);
    static_price_object_construct(&obj3, 1, "obj3", 1.0);
    mu_assert("test_foreach: Testing foreach gather",
              foreach(&head, gather, data).ptr == (void*)&price[3]);
    mu_assert("test_foreach: Testing foreach gather",
              approx_equal(price[0], 1.5));
    mu_assert("test_foreach: Testing foreach gather",
              approx_equal(price[1], 3.5));
    mu_assert("test_foreach: Testing foreach gather",
              approx_equal(price[2], 1.0));
    return NULL;
}

char* test_length()
{
    Object obj8;
    Object obj7;
    Object obj6;
    Object obj5;
    Object obj4;
    Object obj3;
    Object obj2;
    Object obj1;
    LinkedListNode node8 = {&obj8, NULL};
    LinkedListNode node7 = {&obj7, &node8};
    LinkedListNode node6 = {&obj6, &node7};
    LinkedListNode node5 = {&obj5, &node6};
    LinkedListNode node4 = {&obj4, &node5};
    LinkedListNode node3 = {&obj3, &node4};
    LinkedListNode node2 = {&obj2, &node3};
    LinkedListNode node1 = {&obj1, &node2};
    LinkedListNode* head = &node1;
    mu_assert("test_length: Testing list length is correct",
              length(&head) == 8);
    node5.next = NULL;
    mu_assert("test_length: Testing list length is correct",
              length(&head) == 5);
    node3.next = NULL;
    mu_assert("test_length: Testing list length is correct",
              length(&head) == 3);
    head = NULL;
    mu_assert("test_length: Testing empty list length is correct",
              length(&head) == 0);
    return NULL;
}

static int merge_compare(Object* obj1, Object* obj2) {
    return (int)(((long)obj1) - ((long)obj2));
}

char* test_merge()
{
    LinkedListNode node8 = {(Object*)8, NULL};
    LinkedListNode node7 = {(Object*)7, NULL};
    LinkedListNode node6 = {(Object*)6, &node8};
    LinkedListNode node5 = {(Object*)5, &node6};
    LinkedListNode node4 = {(Object*)4, &node7};
    LinkedListNode node3 = {(Object*)3, &node4};
    LinkedListNode node2 = {(Object*)2, &node5};
    LinkedListNode node1 = {(Object*)1, &node3};
    LinkedListNode* head2 = &node1;
    LinkedListNode* head1 = &node2;
    LinkedListIterator iter;
    merge(&head1, &head2, merge_compare);
    mu_assert("test_merge: Testing list 2 is empty",
              head2 == NULL);
    iterator_begin(&iter, &head1);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == NULL);

    // Split lists and test merge again
    head2 = &node5;
    node4.next = NULL;
    merge(&head1, &head2, merge_compare);
    mu_assert("test_merge: Testing list 2 is empty",
              head2 == NULL);
    iterator_begin(&iter, &head1);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == NULL);

    // Split lists and test merge again
    head2 = head1;
    head1 = &node5;
    node4.next = NULL;
    merge(&head1, &head2, merge_compare);
    mu_assert("test_merge: Testing list 2 is empty",
              head2 == NULL);
    iterator_begin(&iter, &head1);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_merge: Testing merged list is correct",
              iterator_get_object(&iter) == NULL);
    return NULL;
}

char* test_split()
{
    Object obj8;
    Object obj7;
    Object obj6;
    Object obj5;
    Object obj4;
    Object obj3;
    Object obj2;
    Object obj1;
    LinkedListNode node8 = {&obj8, NULL};
    LinkedListNode node7 = {&obj7, &node8};
    LinkedListNode node6 = {&obj6, &node7};
    LinkedListNode node5 = {&obj5, &node6};
    LinkedListNode node4 = {&obj4, &node5};
    LinkedListNode node3 = {&obj3, &node4};
    LinkedListNode node2 = {&obj2, &node3};
    LinkedListNode node1 = {&obj1, &node2};
    LinkedListNode* head1 = &node1;
    LinkedListNode* head2 = NULL;
    LinkedListIterator iter;
    split(&head1, &head2);
    iterator_begin(&iter, &head1);
    mu_assert("test_split: Testing first split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing first split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing first split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing first split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing first split list has correct number of nodes",
              iterator_get_object(&iter) == NULL);
    iterator_begin(&iter, &head2);
    mu_assert("test_split: Testing second split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing second split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing second split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing second split list has correct number of nodes",
              iterator_get_object(&iter) != NULL);
    iterator_next(&iter);
    mu_assert("test_split: Testing second split list has correct number of nodes",
              iterator_get_object(&iter) == NULL);
    return NULL;
}

char* test_mergesort()
{
    LinkedListNode node8 = {(Object*)7, NULL};
    LinkedListNode node7 = {(Object*)4, &node8};
    LinkedListNode node6 = {(Object*)6, &node7};
    LinkedListNode node5 = {(Object*)1, &node6};
    LinkedListNode node4 = {(Object*)2, &node5};
    LinkedListNode node3 = {(Object*)8, &node4};
    LinkedListNode node2 = {(Object*)3, &node3};
    LinkedListNode node1 = {(Object*)5, &node2};
    LinkedListNode* head = &node1;
    LinkedListNode* reverse = NULL;
    LinkedListNode* empty = NULL;
    LinkedListIterator iter;
    LinkedListIterator iter_reverse;
    mergesort(&head, merge_compare);
    iterator_begin(&iter, &head);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == NULL);
    // Test sorted case
    mergesort(&head, merge_compare);
    iterator_begin(&iter, &head);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == NULL);
    // Test reverse sorted case
    iterator_begin(&iter, &head);
    while (!iterator_at_end(&iter)) {
        iterator_begin(&iter_reverse, &reverse);
        iterator_insert_before(&iter_reverse, iterator_remove(&iter));
    }
    mergesort(&reverse, merge_compare);
    iterator_begin(&iter, &reverse);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)1);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)2);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)3);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)4);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)5);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)6);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)7);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == (Object*)8);
    iterator_next(&iter);
    mu_assert("test_mergesort: Testing sorted list is correct",
              iterator_get_object(&iter) == NULL);

    mergesort(&empty, merge_compare);
    mu_assert("test_mergesort: Testing sorting an empty list",
              empty == NULL);
    return NULL;
}

typedef char* (*test_fn_t)();
typedef struct {
    char* name;
    test_fn_t test;
} test_t;

test_t tests[] = {{"test_static_price_object", test_static_price_object},
                  {"test_dynamic_price_object", test_dynamic_price_object},
                  {"test_polymorphism", test_polymorphism},
                  {"test_compare_by_quantity", test_compare_by_quantity},
                  {"test_compare_by_price", test_compare_by_price},
                  {"test_static_bulk_price", test_static_bulk_price},
                  {"test_dynamic_bulk_price", test_dynamic_bulk_price},
                  {"test_iterator_basic", test_iterator_basic},
                  {"test_iterator_remove", test_iterator_remove},
                  {"test_iterator_insert", test_iterator_insert},
                  {"test_max_min_avg_price", test_max_min_avg_price},
                  {"test_foreach", test_foreach},
                  {"test_length", test_length},
                  {"test_merge", test_merge},
                  {"test_split", test_split},
                  {"test_mergesort", test_mergesort}};
size_t num_tests = sizeof(tests)/sizeof(tests[0]);

char* single_test(test_fn_t test, size_t iters) {
    for (size_t i = 0; i < iters; i++) {
        mu_run_test(test);
    }
    return NULL;
}

char* all_tests(size_t iters) {
    for (size_t i = 0; i < num_tests; i++) {
        char* result = single_test(tests[i].test, iters);
        if (result != NULL) {
            return result;
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    char* result = NULL;
    size_t iters = 1;
    if (argc == 1) {
        result = all_tests(iters);
        if (result != NULL) {
            printf("%s\n", result);
        } else {
            printf("ALL TESTS PASSED\n");
        }

        printf("Tests run: %d\n", tests_run);
 
        return result != NULL;
    } else if (argc == 3) {
        iters = (size_t)atoi(argv[2]);
    } else if (argc > 3) {
        printf("Wrong number of arguments, only one test is accepted at time");
    }

    result = "Did not find test";

    for (size_t i = 0; i < num_tests; i++) {
        if (string_equal(argv[1], tests[i].name)) {
            result = single_test(tests[i].test, iters);
            break;
        }
    }
    if (result) {
        printf("%s\n", result);
    }
    else {
        printf("ALL TESTS PASSED\n");
    }

    printf("Tests run: %d\n", tests_run);

    return result != NULL;

}

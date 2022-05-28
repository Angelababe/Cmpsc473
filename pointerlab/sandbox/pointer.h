#ifndef POINTER_H
#define POINTER_H

#include <stdio.h>
#include <stdbool.h>
#include <math.h>

//
// Constants
//

static const double ERR_OUT_OF_STOCK = -1.0;
static const int ERR_INSERT_AFTER_END = -2;
static const double BULK_DISCOUNT = 0.9;

//
// Structure definitions and function pointer typedefs
//

typedef double (*price_fn)(void* obj);
typedef double (*bulk_price_fn)(void* obj, unsigned int quantity);
typedef struct {
    struct {
        price_fn price;
        bulk_price_fn bulk_price;
    } virtual_func_table;
    unsigned int quantity;
    const char* name;
} Object;

typedef struct {
    Object obj;
    double price;
} StaticPriceObject;

typedef struct {
    Object obj;
    double base;
    double factor;
} DynamicPriceObject;

typedef struct LinkedListNode_s {
    Object* obj;
    struct LinkedListNode_s* next;
} LinkedListNode;

typedef struct {
    LinkedListNode** prev_next;
    LinkedListNode* curr;
} LinkedListIterator;

typedef union {
    void* ptr;
    int i;
    long l;
    double d;
    float f;
} Data;

typedef Data (*foreach_fn)(Object* obj, Data data);
typedef int (*compare_fn)(Object* obj1, Object* obj2);

//
// Object functions
//

// Returns the price of an object
static inline double object_price(Object* obj)
{
    return obj->virtual_func_table.price(obj);
}

// Returns the bulk price of an object
static inline double object_bulk_price(Object* obj, unsigned int quantity)
{
    return obj->virtual_func_table.bulk_price(obj, quantity);
}

// Returns the quantity of an object
static inline unsigned int object_quantity(Object* obj)
{
    return obj->quantity;
}

// Returns the name of an object
static inline const char* object_name(Object* obj)
{
    return obj->name;
}

// Prints info about an object
static inline void object_print(Object* obj)
{
    printf("%s ($%.2f): %u\n", object_name(obj), object_price(obj), object_quantity(obj));
}

int compare_by_price(Object* obj1, Object* obj2);

int compare_by_quantity(Object* obj1, Object* obj2);

void static_price_object_construct(StaticPriceObject* obj, unsigned int quantity, const char* name, double price);

void dynamic_price_object_construct(DynamicPriceObject* obj, unsigned int quantity, const char* name, double base, double factor);

double static_price(StaticPriceObject* obj);

double dynamic_price(DynamicPriceObject* obj);

double static_bulk_price(StaticPriceObject* obj, unsigned int quantity);

double dynamic_bulk_price(DynamicPriceObject* obj, unsigned int quantity);

//
// Iterator functions
//

void iterator_begin(LinkedListIterator* iter, LinkedListNode** head);

void iterator_next(LinkedListIterator* iter);

bool iterator_at_end(LinkedListIterator* iter);

Object* iterator_get_object(LinkedListIterator* iter);

LinkedListNode* iterator_remove(LinkedListIterator* iter);

int iterator_insert_after(LinkedListIterator* iter, LinkedListNode* node);

void iterator_insert_before(LinkedListIterator* iter, LinkedListNode* node);

//
// List functions
//

void max_min_avg_price(LinkedListNode** head, double* max, double* min, double* avg);

Data foreach(LinkedListNode** head, foreach_fn func, Data data);

int length(LinkedListNode** head);

//
// Mergesort
//

void merge(LinkedListNode** list1_head, LinkedListNode** list2_head, compare_fn compare);

void split(LinkedListNode** head, LinkedListNode** split_head);

void mergesort(LinkedListNode** head, compare_fn compare);

#endif // POINTER_H

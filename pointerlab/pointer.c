// DO NOT INCLUDE ANY OTHER LIBRARIES/FILES
#include "pointer.h"

// In this assignment, you can assume that function parameters are valid and the memory is managed by the caller

// Compares the price of obj1 with obj2
// Returns a negative number if the price of obj1 is less than the price of obj2
// Returns a positive number if the price of obj1 is greater than the price of obj2
// Returns 0 if the price of obj1 is equal to the price of obj2
int compare_by_price(Object* obj1, Object* obj2)
{
    // IMPLEMENT THIS
	if (obj1->virtual_func_table.price(obj1) == obj2->virtual_func_table.price(obj2))
		return 0;
	if (obj1->virtual_func_table.price(obj1) > obj2->virtual_func_table.price(obj2))
		return 1;
	if (obj1->virtual_func_table.price(obj1) < obj2->virtual_func_table.price(obj2))
		return -1;
	return 0;
}

// Compares the quantity of obj1 with obj2
// Returns a negative number if the quantity of obj1 is less than the quantity of obj2
// Returns a positive number if the quantity of obj1 is greater than the quantity of obj2
// Returns 0 if the quantity of obj1 is equal to the quantity of obj2
int compare_by_quantity(Object* obj1, Object* obj2)
{
    // IMPLEMENT THIS
	if (obj1->quantity == obj2->quantity)
		return 0;
	if (obj1->quantity > obj2->quantity)
		return 1;
	if (obj1->quantity < obj2->quantity)
		return -1;
	return 0;
}

// Initializes a StaticPriceObject with the given quantity, name, and price
// Memory for the name string is managed by the caller and assumed to be valid for the duration of the object's lifespan
void static_price_object_construct(StaticPriceObject* obj, unsigned int quantity, const char* name, double price)
{
    // IMPLEMENT THIS
	obj->obj.virtual_func_table.price = (price_fn) static_price;
	obj->obj.virtual_func_table.bulk_price = (bulk_price_fn)static_bulk_price;
	
	obj->price = price;
	obj->obj.quantity = quantity;
	obj->obj.name = name;
	
}

// Initializes a DynamicPriceObject with the given quantity, name, base price, and price scaling factor
// Memory for the name string is managed by the caller and assumed to be valid for the duration of the object's lifespan
void dynamic_price_object_construct(DynamicPriceObject* obj, unsigned int quantity, const char* name, double base, double factor)
{
    // IMPLEMENT THIS
	obj->obj.virtual_func_table.price = (price_fn)dynamic_price;
	obj->obj.virtual_func_table.bulk_price = (bulk_price_fn)dynamic_bulk_price;
	
	obj->base = base;
	obj->factor = factor;
	obj->obj.quantity = quantity;
	obj->obj.name = name;
}

// Returns the price of a StaticPriceObject or ERR_OUT_OF_STOCK if it is out of stock
double static_price(StaticPriceObject* obj)
{
    // IMPLEMENT THIS
	if (obj->obj.quantity <= 0)
		return ERR_OUT_OF_STOCK;
	else
		return obj->price;
    return 0;
}

// Returns the price of a DynamicPriceObject or ERR_OUT_OF_STOCK if it is out of stock
// The dynamic price is calculated as the base price multiplied by (the quantity raised to the power of the scaling factor)
double dynamic_price(DynamicPriceObject* obj)
{
    // IMPLEMENT THIS
	if (obj->obj.quantity <=0)
		return ERR_OUT_OF_STOCK;
	else{
		double newprice = 0;
		newprice = obj->base * pow(obj->obj.quantity, obj->factor);
		return newprice;
	}
    return 0;
}

// Returns the bulk price of purchasing multiple (indicated by quantity parameter) StaticPriceObject at a discount where the first item is regular price and the additional items are scaled by the BULK_DISCOUNT factor
// Return ERR_OUT_OF_STOCK of there is insufficient quantity available
double static_bulk_price(StaticPriceObject* obj, unsigned int quantity)
{
    // IMPLEMENT THIS
	if (quantity == 0)
		return 0;
	if (obj->obj.quantity < quantity)
		return ERR_OUT_OF_STOCK;
	else{
		double newprice = 0;
		newprice = obj->price + obj->price * BULK_DISCOUNT * (quantity - 1);
		return newprice;
	}
    return 0;
}

// Returns the bulk price of purchasing multiple (indicated by quantity parameter) DynamicPriceObject at a discount where the first item is regular price and the additional items are scaled by the BULK_DISCOUNT factor
// This uses the same dynamic price equation from the dynamic_price function, and note that the price changes for each item that is bought
// For example, if 3 items are requested, each of them will have a different price, and this function calculates the total price of all 3 items
// Return ERR_OUT_OF_STOCK of there is insufficient quantity available
double dynamic_bulk_price(DynamicPriceObject* obj, unsigned int quantity)
{
    // IMPLEMENT THIS
	if (quantity == 0)
		return 0;
	if (obj->obj.quantity < quantity)
		return ERR_OUT_OF_STOCK;
	else{
		double newprice = 0;
		int first = 0;
		for (unsigned int i = 0; i < quantity; i++){
			if (first == 0){
				newprice += obj->base * pow(obj->obj.quantity - i, obj->factor);
				first ++;
			}
			else{
				newprice += obj->base * pow(obj->obj.quantity - i, obj->factor) * BULK_DISCOUNT ;
			}
		}
		return newprice;
	}
    return 0;
}

//
//
//

// Initializes an iterator to the beginning of a list
void iterator_begin(LinkedListIterator* iter, LinkedListNode** head)
{
    // IMPLEMENT THIS
	iter->prev_next = head;
	iter->curr = *head;
	head = iter->prev_next;
}

// Updates an iterator to move to the next element in the list if possible
void iterator_next(LinkedListIterator* iter)
{
    // IMPLEMENT THIS
	if (!iterator_at_end(iter)){
		//iter->prev_next = &iter->curr->next;
		iter->prev_next = &iter->curr->next;
		iter->curr = iter->curr->next;
	}	
}

// Returns true if iterator is at the end of the list or false otherwise
// The end of the list is the position after the last node in the list
bool iterator_at_end(LinkedListIterator* iter)
{
    // IMPLEMENT THIS
	if (iter->curr == NULL)
		return true;
    return false;
}

// Returns the current object that the iterator references or NULL if the iterator is at the end of the list
Object* iterator_get_object(LinkedListIterator* iter)
{
    // IMPLEMENT THIS
	if (!iterator_at_end(iter))
		return iter->curr->obj;
	return NULL;
}

// Removes the current node referenced by the iterator
// The iterator is valid after call and references the next object
// Returns removed node
LinkedListNode* iterator_remove(LinkedListIterator* iter)
{
    //IMPLEMENT THIS
	LinkedListNode* removenode;
	removenode = iter->curr;
	*iter->prev_next = iter->curr->next;
	iter->curr = iter->curr->next;
    return removenode;
}

// Inserts node after the current node referenced by the iterator
// The iterator is valid after call and references the same object as before
// Returns ERR_INSERT_AFTER_END error if iterator at the end of the list or 0 otherwise
int iterator_insert_after(LinkedListIterator* iter, LinkedListNode* node)
{
    // IMPLEMENT THIS
	if (!iterator_at_end(iter)){
		node->next = iter->curr->next;
		iter->curr->next = node;
		return 0;
	}
	else{
		return ERR_INSERT_AFTER_END;
	}
}

// Inserts node before the current node referenced by the iterator
// The iterator is valid after call and references the same object as before
void iterator_insert_before(LinkedListIterator* iter, LinkedListNode* node)
{
    // IMPLEMENT THIS
	*iter->prev_next = node;
	node->next = iter->curr;
	iter->prev_next = &node->next;
}

//
// List functions
//

// Returns the maximum, minimum, and average price of the linked list
void max_min_avg_price(LinkedListNode** head, double* max, double* min, double* avg)
{
    // IMPLEMENT THIS
	LinkedListIterator iter;
	iterator_begin(&iter,head);
	*min = iterator_get_object(&iter)->virtual_func_table.price(iterator_get_object(&iter));
	int num = 0;
	while (!iterator_at_end(&iter)){
		double newprice;
		newprice = iterator_get_object(&iter)->virtual_func_table.price(iterator_get_object(&iter));
		*avg += newprice;
		if (newprice > *max)
			*max = newprice;
		if (newprice < *min)
			*min = newprice;
		num++;
		iterator_next(&iter);	
	}
	*avg = *avg/num;
}

// Executes the func function for each node in the list
// The function takes in an input data and returns an output data, which is used as input to the next call to the function
// The initial input data is provided as a parameter to foreach, and foreach returns the final output data
// For example, if there are three nodes, foreach should behave like: return func(node3, func(node2, func(node1, data)))
Data foreach(LinkedListNode** head, foreach_fn func, Data data)
{
    // IMPLEMENT THIS
	LinkedListIterator iter;
	iterator_begin(&iter,head);
	while(!iterator_at_end(&iter)){
		data = func(iterator_get_object(&iter),data);
		iterator_next(&iter);
	}
    return data;
}

// Returns the length of the list
int length(LinkedListNode** head)
{
    // IMPLEMENT THIS
	LinkedListIterator iter;
	iterator_begin(&iter,head);
	int length =0;
	while(!iterator_at_end(&iter)){
		length++;
		iterator_next(&iter);
	}
    return length;
}

//
// Mergesort
//

// Assuming list1 and list2 are sorted lists, merge list2 into list1 while keeping it sorted
// That is, when the function returns, list1 will have all the nodes in sorted order and list2 will be empty
// The sort order is determined by the compare function
// Default convention for compare functions on objects A and B:
//   Negative return values indicate A should be earlier than B in the list
//   Positive return values indicate A should be later than B in the list
//   Zero return values indicate A and B are equal
// A stable sort is not required for this implementation, so equal objects can be in either order
void merge(LinkedListNode** list1_head, LinkedListNode** list2_head, compare_fn compare)
{
    // IMPLEMENT THIS
	LinkedListIterator iter1;
	LinkedListIterator iter2;
	iterator_begin(&iter1,list1_head);
	iterator_begin(&iter2,list2_head);
	while(!iterator_at_end(&iter2)){
		if (iterator_at_end(&iter1)){
			LinkedListNode* removenode = iterator_remove(&iter2);
			iterator_insert_before(&iter1,removenode);
		}
		else{
			Object* obj1 = iterator_get_object(&iter1);
			Object* obj2 = iterator_get_object(&iter2);
			int comparison = compare(obj1,obj2);	
			if (comparison<=0){
				iterator_next(&iter1);
			}
			else{
				LinkedListNode* removenode = iterator_remove(&iter2);
				iterator_insert_before(&iter1,removenode);
			}
		}
	}
}

// Split the list head in half and place half in the split list
// For example, if head has 8 nodes, then split will move 4 of them to split_head
void split(LinkedListNode** head, LinkedListNode** split_head)
{
    // IMPLEMENT THIS
	LinkedListIterator iter1;
	LinkedListIterator iter2;
	iterator_begin(&iter1,head);
	iterator_begin(&iter2,split_head);
	int listlength = length(head);
	if ((listlength%2 == 0)&&(listlength!=0)){
		listlength = listlength/2;
		for (int i = 1; i<=listlength; i++){
			iterator_next(&iter1);
		}
		while (!iterator_at_end(&iter1)){
			LinkedListNode* removenode = iterator_remove(&iter1);
			iterator_insert_before(&iter2,removenode);
		}
	}
	else if (listlength!=0){
		listlength = (listlength+1)/2;
		for (int i = 1; i<=listlength; i++){
			iterator_next(&iter1);
		}
		while (!iterator_at_end(&iter1)){
			LinkedListNode* removenode = iterator_remove(&iter1);
			iterator_insert_before(&iter2,removenode);
		}
	}
}

// Implement the mergesort algorithm to sort the list
// The sort order is determined by the compare function
// Default convention for compare functions on objects A and B:
//   Negative return values indicate A should be earlier than B in the list
//   Positive return values indicate A should be later than B in the list
//   Zero return values indicate A and B are equal
// A stable sort is not required for this implementation, so equal objects can be in either order
void mergesort(LinkedListNode** head, compare_fn compare)
{
    // IMPLEMENT THIS
	LinkedListIterator iter;
	iterator_begin(&iter,head);
	if(length(head)>1){
		LinkedListNode* head2 = NULL;
		split(head,&head2);
		mergesort(head,compare);
		mergesort(&head2,compare);
		merge(head,&head2,compare);
	}
}

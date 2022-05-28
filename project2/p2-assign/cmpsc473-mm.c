
/**********************************************************************

   File          : cmpsc473-mm.c

   Description   : Slab allocation and defenses

***********************************************************************/
/**********************************************************************
Copyright (c) 2019 The Pennsylvania State University
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of The Pennsylvania State University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***********************************************************************/
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <time.h> 
#include "cmpsc473-format-156.h"   // TASK 1: student-specific
#include "cmpsc473-mm.h"

/* Globals */
heap_t *mmheap;
unsigned int canary;


/* Defines */
#define FREE_ADDR( slab ) ( (unsigned long)slab->start + ( slab->obj_size * slab->bitmap->free ))


/**********************************************************************

    Function    : mm_init
    Description : Initialize slab allocation
    Inputs      : void
    Outputs     : 0 if success, -1 on error

***********************************************************************/

int mm_init( void )
{
	mmheap = (heap_t *)malloc( sizeof(heap_t) );
	if ( !mmheap ) return -1;

	// TASK 2: Initialize heap memory (using regular 'malloc') and 
	//   heap data structures in prep for malloc/free
	unsigned char *start = (unsigned char *)malloc(HEAP_SIZE+PAGE_SIZE);
	mmheap->start = (void *)(((unsigned long)start+PAGE_SIZE-1) & PAGE_MASK);
	mmheap->slabA = (slab_cache_t *)malloc(sizeof(slab_cache_t));
	mmheap->slabB = (slab_cache_t *)malloc(sizeof(slab_cache_t));
	mmheap->slabC = (slab_cache_t *)malloc(sizeof(slab_cache_t));
	mmheap->size = HEAP_SIZE;
	mmheap->bitmap = (bitmap_t *)malloc(sizeof(bitmap_t));
	mmheap->bitmap->free = 0;
	mmheap->bitmap->size = 256;
	int i;
	mmheap->bitmap->map = (word_t *)malloc(32 * sizeof(word_t));
	for(i=0; i<32; i++){
		mmheap->bitmap->map[i] = 0;
	}
	slab_t* slab;
	int b;
	for(b=0; b<256 ; b++){
		slab=(slab_t *) (mmheap->start +PAGE_SIZE*b- 64);
		slab->state = 0;
		slab->start = mmheap->start +PAGE_SIZE*(b-1);
		double offset = 4096/56;
		if(b==0){
			//printf("%d \n", sizeof(sizeof(slab_t)));
			slab->prev = (slab_t *)((char *)slab + PAGE_SIZE*255);
			slab->next = (slab_t *)((char *)slab +4096);
		}
		else if(b == 255){
			slab->prev = (slab_t *)((char *)slab -4096);
			slab->next = (slab_t *)((char *)slab -4096*255);
		}
		else{
			slab->next = (slab_t *)((char *)slab +4096);
			slab->prev = (slab_t *)((char *)slab -4096);
		}
		slab->bitmap = (bitmap_t *)malloc(sizeof(bitmap_t));
		slab->bitmap->free = 0;
		slab->bitmap->size = 0;
		slab->bitmap->map = (word_t *)malloc(32 *sizeof(word_t));
		for(i=0; i<32; i++){
			slab->bitmap->map[i] = 0;
		}
		slab->ct = 0;
		slab->num_objs = 0;
		slab->obj_size = 0;
		slab->real_size = 0;
	}
	mmheap->slabA->current = (slab_t *)(mmheap->start+PAGE_SIZE-64);
	mmheap->slabA->ct = 0;
	mmheap->slabA->obj_size = 0;
	mmheap->slabA->malloc_fn = NULL;
	mmheap->slabA->free_fn = NULL;
	mmheap->slabA->canary_fn = NULL;
	mmheap->slabB->current = (slab_t *)(mmheap->start+PAGE_SIZE-64);
	mmheap->slabB->ct = 0;
	mmheap->slabB->obj_size = 0;
	mmheap->slabB->malloc_fn = NULL;
	mmheap->slabB->free_fn = NULL;
	mmheap->slabB->canary_fn = NULL;
	mmheap->slabC->current = (slab_t *)(mmheap->start+PAGE_SIZE-64);
	mmheap->slabC->ct = 0;
	mmheap->slabC->obj_size = 0;
	mmheap->slabC->malloc_fn = NULL;
	mmheap->slabC->free_fn = NULL;
	mmheap->slabC->canary_fn = NULL;

	// initialize canary
	canary_init();
	return 0;
}


/**********************************************************************

    Function    : my_malloc
    Description : Allocate from slabs
    Inputs      : size: amount of memory to allocate
    Outputs     : address if success, NULL on error

***********************************************************************/

void *my_malloc( unsigned int size )
{
	void *addr = (void *) NULL;
	
	// TASK 2: implement malloc function for slab allocator
	slab_cache_t* slab_cache = NULL;
	int type=0;
	//check alloc type
	if(size==sizeof(struct A)){
		slab_cache=mmheap->slabA;
		while(slab_cache->current->state != 0){
			if((slab_cache->current->state == 1)&&(slab_cache->current->bitmap->size == 42)){
				break;
			}
			if(slab_cache->current == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
				slab_cache->current = (slab_t *)(mmheap->start + PAGE_SIZE -64);
				continue;
			}
			slab_cache->current = (slab_t *)((char *)slab_cache->current + 4096);
		}
		type = 1;
	}
	else if(size==sizeof(struct B)){
		slab_cache=mmheap->slabB;
		while(slab_cache->current->state != 0){
			if((slab_cache->current->state == 1)&&(slab_cache->current->bitmap->size == 63)){
				break;
			}
			if(slab_cache->current == (slab_t *)(mmheap->start + 0x100000 - 64- 4096)){
				slab_cache->current = (slab_t *)(mmheap->start + PAGE_SIZE -64);
				continue;
			}//printf("test 1");
			slab_cache->current = (slab_t *)((char *)slab_cache->current + 4096);
		}
		type = 2;
	}
	else if(size==sizeof(struct C)){
		slab_cache=mmheap->slabC;
		while(slab_cache->current->state != 0){
			
			if((slab_cache->current->state == 1)&&(slab_cache->current->bitmap->size == 50)){
				break;
			}
			if(slab_cache->current == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
				slab_cache->current = (slab_t *)(mmheap->start + PAGE_SIZE -64);
				continue;
			}
			slab_cache->current = (slab_t *)((char *)slab_cache->current + 4096);
		}
		type = 3;
	}
	else{
		printf("invalid size value. No struct with such size exists \n");
		return -1;
	}
	
	void *address = (void *)(slab_cache->current)+64-PAGE_SIZE;
	unsigned long index = ((unsigned long)address-(unsigned long)mmheap->start)/PAGE_SIZE;
	//malloc if page is partial
	if(slab_cache->current->state == 1){
		int idx=900;
		int a;
		if(type == 1){
			allocA_t *allocA;
			for(a=0; a<slab_cache->current->bitmap->size; a++){
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 0)&&(idx == 900)){
					idx=a;
				}
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 1)&&(idx != 900)){
					slab_cache->current->obj_size -= allocA_size;
				}
			}
			int count=0;
			while( get_bit(slab_cache->current->bitmap->map, count)){
				count++;
				//printf("test 8\n");
			}
			slab_cache->current->bitmap->free = count;
			slab_cache->current->obj_size += allocA_size;
			slab_cache->current->real_size += sizeof(struct A);
			slab_cache->current->ct += 1;
			set_bit(slab_cache->current->bitmap->map, idx);
			slab_cache->obj_size += sizeof(struct A);
			slab_cache->current->obj_size += allocA_size;
			addr = (void *)(char *)slab_cache->current->start + idx * allocA_size;
			//printf("%d\n", slab_cache->current->ct);
			if(slab_cache->current->ct == slab_cache->current->bitmap->size){
				slab_cache->current->state = 2;
			}
			allocA=(allocA_t *)addr;
			allocA->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct A) + 4);
	fcbit = (unsigned int)((int)addr & FCBITS);
		}
		else if(type == 2){
			allocB_t *allocB;
			for(a=0; a<slab_cache->current->bitmap->size; a++){
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 0)&&(idx == 900)){
					idx=a;
				}
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 1)&&(idx != 900)){
					slab_cache->current->obj_size -= allocB_size;
				}
			}
			int count=0;
			while( get_bit(slab_cache->current->bitmap->map, count)){
				count++;
			}
			slab_cache->current->bitmap->free = count;
			slab_cache->current->obj_size += allocB_size;
			slab_cache->current->real_size += sizeof(struct B);
			slab_cache->current->ct += 1;
			set_bit(slab_cache->current->bitmap->map, idx);
			slab_cache->obj_size += sizeof(struct B);
			slab_cache->current->obj_size += allocB_size;
			addr = slab_cache->current->start + idx * allocB_size;
			if(slab_cache->current->ct == slab_cache->current->bitmap->size){
				slab_cache->current->state = 2;
			}
			allocB=(allocB_t *)addr;
			allocB->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct B) + 4);
	fcbit = (unsigned int)((int)addr & FCBITS);
		}
		else if(type == 3){
			allocC_t *allocC;
			for(a=0; a<slab_cache->current->bitmap->size; a++){
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 0)&&(idx == 900)){
					idx=a;
				}
				if(((get_bit(slab_cache->current->bitmap->map, a)) == 1)&&(idx != 900)){
					slab_cache->current->obj_size -= allocC_size;
				}
			}
			int count=0;
			while( get_bit(slab_cache->current->bitmap->map, count)){
				count++;
			}
			slab_cache->current->bitmap->free = count;
			slab_cache->current->obj_size += allocC_size;
			slab_cache->current->real_size += sizeof(struct C);
			slab_cache->current->ct += 1;
			set_bit(slab_cache->current->bitmap->map, idx);
			slab_cache->obj_size += sizeof(struct C);
			slab_cache->current->obj_size += allocC_size;
			addr = slab_cache->current->start + idx * allocC_size;
			if(slab_cache->current->ct == slab_cache->current->bitmap->size){
				slab_cache->current->state = 2;
			}
			allocC=(allocC_t *)addr;
			allocC->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct C) + 4);
	fcbit = (unsigned int)((int)addr & FCBITS);
		}
	}
	//malloc if page is empty
	else if(slab_cache->current->state == 0){
		slab_cache->current->state = 1;
		slab_cache->ct ++;
		set_bit(mmheap->bitmap->map, index);
		int i;
		if(type == 1){
			allocA_t* allocA;
			slab_t* ref=slab_cache->current;
			slab_cache->current->ct += 1;
			slab_cache->current->num_objs += 1;
			
			slab_cache->current->bitmap->free = 1;
			slab_cache->current->obj_size += allocA_size;
			slab_cache->current->real_size += sizeof(struct A);
			slab_cache->current->bitmap->size = (PAGE_SIZE - 64) / allocA_size;
			for(i=0; i<slab_cache->current->bitmap->size; i++){
				slab_cache->current->bitmap->map[i] = 0;
			}
			set_bit(slab_cache->current->bitmap->map, 0);
			do{
				if(ref == (slab_t *)(mmheap->start + PAGE_SIZE - 64)){
					ref = (slab_t *)(mmheap->start + 0x100000 - 64 - 4096);
					continue;
				}
				ref = (slab_t *)((char *)ref - 4096); //printf("test4 \n");
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current-> prev =ref;
			ref = slab_cache->current;
			do{
				if(ref == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096); //printf("test 5\n");
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current->next = ref;
			ref=slab_cache->current->next;
			ref->prev = slab_cache->current;
			slab_t *ref1=slab_cache->current;
			ref=slab_cache->current->prev;
			while(ref != slab_cache->current){
				ref->next = ref1;
				ref = ref->prev;
				ref1 = ref1->prev;
			}
			slab_cache->obj_size += sizeof(struct A);
			addr = slab_cache->current->start;
			allocA=(allocA_t *) addr;
			allocA->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct A) + 4);
			fcbit = (unsigned int)((int)addr & FCBITS);
		}
		else if(type == 2){
			allocB_t* allocB;
			slab_t* ref=slab_cache->current;
			slab_cache->current->ct += 1;
			slab_cache->current->num_objs += 1;
			
			slab_cache->current->bitmap->free = 1;
			slab_cache->current->obj_size += allocB_size;
			slab_cache->current->real_size += sizeof(struct B);
			slab_cache->current->bitmap->size = (PAGE_SIZE - 64) / allocB_size;
			for(i=0; i<slab_cache->current->bitmap->size; i++){
				slab_cache->current->bitmap->map[WORD_OFFSET(i)] = 0;
			}
			set_bit(slab_cache->current->bitmap->map, 0);
			do{
				//printf("test7 \n");
				if(ref == (slab_t *)(mmheap->start+PAGE_SIZE-64)){
					ref = (slab_t *)(mmheap->start + 0x100000 -64 -4096);
					continue;
				}
				ref = (slab_t *)((char *)ref - 4096);
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current-> prev =ref;
			ref = slab_cache->current;
			do{
				//printf("test6 \n");
				if(ref == (slab_t *)(mmheap->start + 0x100000 - 64 -4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096);
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current->next = ref;
			ref=slab_cache->current->next;
			ref->prev = slab_cache->current;
			slab_t *ref1=slab_cache->current;
			ref=slab_cache->current->prev;
			while(ref != slab_cache->current){
				ref->next = ref1;
				ref = ref->prev;
				ref1 = ref1->prev;
			}
			slab_cache->obj_size += sizeof(struct B);
			addr = slab_cache->current->start;
			allocB=(allocB_t *) addr;
			allocB->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct B) + 4);
			fcbit = (unsigned int)((int)addr & FCBITS);
		}
		else if(type == 3){
			allocC_t* allocC;
			slab_t* ref=slab_cache->current;
			slab_cache->current->ct += 1;
			slab_cache->current->num_objs += 1;
			
			slab_cache->current->bitmap->free = 1;
			slab_cache->current->obj_size += allocC_size;
			slab_cache->current->real_size += sizeof(struct C);
			slab_cache->current->bitmap->size = (PAGE_SIZE - 64) / allocC_size;
			for(i=0; i<slab_cache->current->bitmap->size; i++){
				slab_cache->current->bitmap->map[WORD_OFFSET(i)] = 0;
			}
			set_bit(slab_cache->current->bitmap->map, 0);
			do{
				if(ref == (slab_t *)(mmheap->start+PAGE_SIZE-64)){
					ref = (slab_t *)(mmheap->start + 0x100000 -64 -4096);
					continue;
				}
				ref = (slab_t *)((char *)ref - 4096);
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current-> prev =ref;
			ref = slab_cache->current;
			do{
				if(ref == (slab_t *)(mmheap->start + 0x100000 - 64 - 4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096);
			}while(ref->bitmap->size != slab_cache->current->bitmap->size);
			slab_cache->current->next = ref;
			ref=slab_cache->current->next;
			ref->prev = slab_cache->current;
			slab_t *ref1=slab_cache->current;
			ref=slab_cache->current->prev;
			while(ref != slab_cache->current){
				ref->next = ref1;
				ref = ref->prev;
				ref1 = ref1->prev;
			}
			slab_cache->obj_size += sizeof(struct C);
			addr = slab_cache->current->start;
			allocC=(allocC_t *)addr;
			allocC->canary = canary;
			unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct C) + 4);
			fcbit = (unsigned int)((int)addr & FCBITS);
		}
	}
	
	unsigned int *fcbit = (unsigned int*) (addr+sizeof(struct A) + 4);
	fcbit = (unsigned int)((int)addr & FCBITS);
	

	return addr;	
}



/**********************************************************************

    Function    : my_free
    Description : deallocate from slabs
    Inputs      : buf: full pointer (with counter) to deallocate
    Outputs     : address if success, NULL on error

***********************************************************************/

void my_free( void *buf ){

	// TASK 2: Implement free function for slab allocator
	if(buf == NULL){
		return;
	}
	void* bufptr = (void *)((unsigned long)buf&PAGE_MASK);
	slab_t* slab= (slab_t *)(bufptr+PAGE_SIZE-64);
	if(slab->state==2){
		slab->state = 1;
	}
	slab_cache_t* slab_cache;
	int idx=0;
	// remove the specific alloc
	if(slab->bitmap->size == mmheap->slabA->current->bitmap->size){
		slab_cache = mmheap->slabA;
		while(slab!=slab_cache->current){
			slab_cache->current = slab_cache->current->next;
		}
		while(bufptr!=buf){
			idx++;
			bufptr += allocA_size;
		}
		clear_bit(slab->bitmap->map, idx);
		slab->ct--;
		slab->obj_size -= allocA_size;
		slab->real_size -= sizeof(struct A);
		slab_cache->obj_size -= sizeof(struct A);
		int xdi = idx-1;
		while(get_bit(slab->bitmap->map, xdi)){
			if(xdi == -1){
				slab->bitmap->free = idx;
				break;
			}
			xdi--;
		}
	}
	else if(slab->bitmap->size == mmheap->slabB->current->bitmap->size){
		slab_cache = mmheap->slabB;
		while(slab!=slab_cache->current){
			slab_cache->current = slab_cache->current->next;
		}
		while(bufptr!=buf){
			idx++;
			bufptr += allocB_size;
		}
		clear_bit(slab->bitmap->map, idx);
		slab->ct--;
		slab->obj_size -= allocB_size;
		slab->real_size -= sizeof(struct B);
		slab_cache->obj_size -= sizeof(struct B);
		slab->bitmap->free = idx;
		int xdi = idx -1;
		while(get_bit(slab->bitmap->map, xdi)){
			if(xdi == -1){
				slab->bitmap->free = idx;
				break;
			}
			xdi--;
		}
	}
	else if(slab->bitmap->size == mmheap->slabC->current->bitmap->size){
		slab_cache = mmheap->slabC;
		while(slab!=slab_cache->current){//printf("test 112");
			slab_cache->current = slab_cache->current->next;
		}
		while(bufptr!=buf){
			idx++;
			bufptr += allocC_size;
		}
		clear_bit(slab->bitmap->map, idx);
		slab->ct--;
		slab->obj_size -= allocB_size;
		slab->real_size -= sizeof(struct B);
		slab_cache->obj_size -= sizeof(struct B);
		slab->bitmap->free = idx;
		int xdi = idx-1;
		while(get_bit(slab->bitmap->map, xdi)){
			if(xdi == -1){//printf("test 1111");
				slab->bitmap->free = idx;
				break;
			}
			xdi--;
		}
	}
	
	//free slab if empty
	if(slab->ct == 0){
		if(slab->bitmap->size == mmheap->slabA->current->bitmap->size){
			if(mmheap->slabA->ct != 1){
				mmheap->slabA->ct --;
			}
			slab_t *ref= slab->next;
			while(ref->bitmap->size != slab_cache->current->bitmap->size){
				if(ref == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096); //printf("test 5\n");
				if(ref == slab){
					break;
				}
			}
			mmheap->slabA->current = ref;
		}
		else if(slab->bitmap->size == mmheap->slabB->current->bitmap->size){
			if(mmheap->slabB->ct != 1){
				mmheap->slabB->ct --;
			}
			slab_t *ref= slab->next;
			while(ref->bitmap->size != slab_cache->current->bitmap->size){
				if(ref == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096); //printf("test 5\n");
				if(ref == slab){
					break;
				}
			}
			mmheap->slabB->current = ref;
		}
		else if(slab->bitmap->size == mmheap->slabC->current->bitmap->size){
			if(mmheap->slabC->ct != 1){
				mmheap->slabC->ct --;
			}
			slab_t *ref= slab->next;
			while(ref->bitmap->size != slab_cache->current->bitmap->size){
				if(ref == (slab_t *)(mmheap->start + 0x100000 -64 -4096)){
					ref = (slab_t *)(mmheap->start + PAGE_SIZE -64);
					continue;
				}
				ref = (slab_t *)((char *)ref + 4096); //printf("test 5\n");
				if(ref == slab){
					break;
				}
			}
			mmheap->slabC->current = ref;
		}
		slab->state = 0;
		slab->bitmap->size = 0;
		slab->bitmap->free = 0;
		slab->num_objs = 0;
		slab_t* cur = slab;
		slab_t* curr;
		slab->next->prev = slab->prev;
		slab->prev->next = slab->next;
		/*while(((slab_t *)((char *)cur+4096))->state!=0){//printf("test 1");
			cur=(slab_t *)((char *)cur + 4096);
			if( cur == (slab_t *)(mmheap->start+0x100000 - 64)){
				break;
			};
		}
		//connect it to next empty page
		slab->next = (slab_t *)((char *)cur+4096);
		slab->next->prev = slab;
		cur = slab;
		while(((slab_t *)((char *)cur-4096))->state!=0){//printf("test 2");
			cur=(slab_t *)((char *)cur - 4096);
			if( cur == (slab_t *)(mmheap->start+PAGE_SIZE - 64)){
				break;
			};
		}
		//connect it to prev empty page
		slab->prev = (slab_t *)((char *)cur-4096);
		slab->prev->next = slab;*/
	}
	return;
}


/**********************************************************************

    Function    : canary_init
    Description : Generate random number for canary - fresh each time 
    Inputs      : 
    Outputs     : void

***********************************************************************/

void canary_init( void )
{ 
	// This program will create different sequence of  
	// random numbers on every program run  
	canary = rand();   // fix this 
	printf("canary is %d\n", canary );
} 


/**********************************************************************

    Function    : check_canary
    Description : Find canary for obj and check against program canary
    Inputs      : addr: address of object
                  size: size of object to find cache
    Outputs     : 0 for success, -1 for failure

***********************************************************************/

int check_canary( void *addr)
{
	// TASK 3: Implement canary defense
	void* start = (void *)((unsigned long)addr & PAGE_MASK);
	slab_t *slab = (slab_t *)(start + PAGE_SIZE - 64);
	if(slab->bitmap->size == 0){
		printf("memory not used");
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabA->current->bitmap->size){
		unsigned int *canaryptr = (unsigned int *)addr + sizeof(struct A);
		if (canaryptr == canary){
			return 0;
		}
		return -1;
	}
	else if(slab->bitmap->size == mmheap->slabB->current->bitmap->size){
		unsigned int *canaryptr = (unsigned int *)addr + sizeof(struct B);
		if (canaryptr == canary){
			return 0;
		}
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabC->current->bitmap->size){
		unsigned int *canaryptr = (unsigned int *)addr + sizeof(struct C);
		if (canaryptr == canary){
			return 0;
		}
		return -1;
	}
	return 0;
}


/**********************************************************************

    Function    : check_type
    Description : Verify type requested complies with object 
    Inputs      : addr: address of object
                  type: type requested
    Outputs     : 0 on success, -1 on failure

***********************************************************************/

int check_type( void *addr, char type ) 
{
	// TASK 3: Implement type confusion defense
	void* start = (void *)((unsigned long)addr & PAGE_MASK);
	slab_t *slab = (slab_t *)(start + PAGE_SIZE - 64);
	if(slab->bitmap->size == 0){
		printf("memory not used");
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabA->current->bitmap->size){
		char t='A';
		if(t==type){
			return 0;
		}
		return -1;
	}
	else if(slab->bitmap->size == mmheap->slabB->current->bitmap->size){
		char t='B';
		if(t==type){
			return 0;
		}
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabC->current->bitmap->size){
		char t='C';
		if(t==type){
			return 0;
		}
		return -1;
	}
	return 0;
}


/**********************************************************************

    Function    : check_count
    Description : Verify that pointer count equals object count
    Inputs      : addr: address of pointer (must include metadata in pointer)
    Outputs     : 0 on success, or -1 on failure

***********************************************************************/

int check_count( void *addr ) 
{
	// TASK 3: Implement free count defense
	void* start = (void *)((unsigned long)addr & PAGE_MASK);
	slab_t *slab = (slab_t *)(start + PAGE_SIZE - 64);
	if(slab->bitmap->size == 0){
		printf("memory not used");
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabA->current->bitmap->size){
		unsigned int *fcbit1 = (unsigned int*) (addr+sizeof(struct A) + 4);
		int fcbit = (unsigned int)((int)addr & FCBITS);
		if(fcbit==fcbit1){
			return 0;
		}
		return -1;
	}
	else if(slab->bitmap->size == mmheap->slabB->current->bitmap->size){
		unsigned int *fcbit1 = (unsigned int*) (addr+sizeof(struct B) + 4);
		int fcbit = (unsigned int)((int)addr & FCBITS);
		if(fcbit==fcbit1){
			return 0;
		}
		return -1;
	}
	if(slab->bitmap->size == mmheap->slabC->current->bitmap->size){
		unsigned int *fcbit1 = (unsigned int*) (addr+sizeof(struct C) + 4);
		int fcbit = (unsigned int)((int)addr & FCBITS);
		if(fcbit==fcbit1){
			return 0;
		}
		return -1;
	}
	return 0;
}



/**********************************************************************

    Function    : set/clear/get_bit
    Description : Bit manipulation functions
    Inputs      : words: bitmap 
                  n: index in bitmap
    Outputs     : cache if success, or NULL on failure

***********************************************************************/

void set_bit(word_t *words, int n) {
	words[WORD_OFFSET(n)] |= (1 << BIT_OFFSET(n));
}

void clear_bit(word_t *words, int n) {
	words[WORD_OFFSET(n)] &= ~(1 << BIT_OFFSET(n));
}

int get_bit(word_t *words, int n) {
	word_t bit = words[WORD_OFFSET(n)] & (1 << BIT_OFFSET(n));
	return bit != 0;
}


/**********************************************************************

    Function    : print_cache_slabs
    Description : Print current slab list of cache
    Inputs      : cache: slab cache
    Outputs     : void

***********************************************************************/

int print_cache_slabs( slab_cache_t *cache )
{
	slab_t *slab = cache->current;
	int count=0;
	printf("Cache %p has %d slabs\n", cache, cache->ct );
	do {
		printf("slab: %p; prev: %p; next: %p\n", slab, slab->prev, slab->next );
		count+=1;
		slab = slab->next;
	} while ( slab != cache->current );
	return count;
}


/**********************************************************************

    Function    : get_stats/slab_counts
    Description : Print stats on slab page and object allocations 
    Outputs     : void

***********************************************************************/

void slab_counts( slab_cache_t *cache, unsigned int *slab_count, unsigned int *object_count ){
	slab_t *slab = cache->current;
	int i;
	unsigned int orig_count;
	
	*slab_count = 0;
	*object_count = 0;
	
	if ( slab == NULL ) {
        return;
    }
	do {
		(*slab_count)++;
		// set orig to test objects per slab
		orig_count = *object_count;

		// count objects in slab
		for ( i = 0; i < slab->bitmap->size ; i++ ) {
			if ( get_bit( slab->bitmap->map, i )) {
				(*object_count)++;
			}
		}

		if (( *object_count - orig_count ) != slab->ct ) {
			printf("*** Discrepancy in object count in slab %p: %d:%d\n", 
			       slab, *object_count - orig_count, slab->ct);
		}
			

		slab = slab->next;
		//printf("%d \n", slab->state);
	} while ( slab != cache->current );

	if ( *slab_count != cache->ct ) {
		printf("*** Discrepancy in slab page count in cache %p: %d:%d\n", cache, *slab_count, cache->ct);
	}
}

void get_stats(){
	unsigned int slab_count, object_count;

	printf("--- Cache A ---\n");
	slab_counts( mmheap->slabA, &slab_count, &object_count );
	printf("Number of slab pages:objects in Cache A: %d:%d\n", slab_count, object_count );
	printf("--- Cache B ---\n");
	slab_counts( mmheap->slabB, &slab_count, &object_count );
	printf("Number of slab pages:objects in Cache B: %d:%d\n", slab_count, object_count );
	printf("--- Cache C ---\n");
	slab_counts( mmheap->slabC, &slab_count, &object_count );
	printf("Number of slab pages:objects in Cache C: %d:%d\n", slab_count, object_count );
}

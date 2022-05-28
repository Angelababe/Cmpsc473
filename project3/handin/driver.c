//···········································································································································································
#include "driver.h"
	int count=0;
	int test=0;
driver_t* driver_create(size_t size){
	//size > 0, create a queued driver
	if(size > 0){
		driver_t* driver = malloc (sizeof(driver_t));
		sem_init(&driver->size, 0, (unsigned int) size);
		sem_init(&driver->jobs, 0, 0);
		sem_init(&driver->mutex, 0, 1);
		sem_init(&driver->handle, 0, 1);
		driver->job = NULL;
		driver->close = 1;
		driver->unqueue = 1;
		driver->isschedule = 0;
		driver->queue = queue_create(size);
		driver->count = count;
		count++;
		return driver;
	}
	//size = 0, create an unqueued driver
	else if(size == 0){	
		driver_t* driver = malloc (sizeof(driver_t));
		sem_init(&driver->size, 0, 1);
		sem_init(&driver->jobs, 0, 0);
		sem_init(&driver->mutex, 0, 1);
		sem_init(&driver->handle, 0, 0);
		driver->job = NULL;
		driver->handlequeue=0;
		driver->close = 1;
		driver->unqueue = 0;
		driver->isschedule = 0;
		driver->queue = queue_create((size_t) 1);
		driver->count = count;
		count++;
		return driver;
	}
	//size < 0, fail to create driver
	else {
		return NULL;
	}
}

enum driver_status driver_schedule(driver_t *driver, void* job) {
	
	sem_wait(&driver->size);	//wait until partial queue
	if(driver->close == 0){			//driver is closed, return CLOSED_ERR
		sem_post(&driver->size);
		sem_post(&driver->mutex);
		
		return DRIVER_CLOSED_ERROR;
	}
	if(driver->unqueue == 0){
		sem_wait(&driver->mutex);
		if(driver->handlequeue == 0){
			driver->handlequeue --;
			
			int jobssize;
			sem_getvalue(&driver->jobs, &jobssize);
			int sizesize;
			sem_getvalue(&driver->size, &sizesize);
			driver->job = job;
			sem_post(&driver->jobs);
			sem_post(&driver->mutex);
			return SUCCESS;
		}
		else if(driver->handlequeue < 0){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_FULL;
		}
		driver->job = job;
		driver->handlequeue --;
		sem_post(&driver->jobs);
		sem_post(&driver->mutex);
		return SUCCESS;
	}
	sem_wait(&driver->mutex);
	enum queue_status qs= queue_add (driver->queue, job);
	if(qs == QUEUE_ERROR){			//queue error, return GEN_ERR
		sem_post(&driver->mutex);
		return DRIVER_GEN_ERROR;
	}
	sem_post(&driver->jobs);
	sem_post(&driver->mutex);			//successful adding, return SUCCESS
	return SUCCESS;
}

enum driver_status driver_handle(driver_t *driver, void **job) {
	
	
	sem_wait(&driver->jobs);
	
	if(driver->close == 0){
		sem_post(&driver->jobs);
		sem_post(&driver->mutex);
		return DRIVER_CLOSED_ERROR;
	}
	
	
	if(driver->unqueue == 0){
		sem_wait(&driver->mutex);
		if(driver->handlequeue == 0){
			driver->handlequeue ++;
			
			*job = driver->job;
			
			sem_post(&driver->size);
			sem_post(&driver->mutex);
			return SUCCESS;
		}
		else if(driver->handlequeue > 0){
			//sem_post(&driver->jobs);
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_EMPTY;
		}
			
		*job = driver->job;
		driver->handlequeue ++;
		sem_post(&driver->size);
		sem_post(&driver->mutex);
		return SUCCESS;
	}
	sem_wait(&driver->mutex);
	enum queue_status qs = queue_remove(driver->queue, job);
	if(qs == QUEUE_ERROR){
		sem_post(&driver->mutex);
		return DRIVER_GEN_ERROR;
	}
	
	
		//printf("handle job is: %s\n", *job);
	sem_post(&driver->size);
	sem_post(&driver->mutex);
	return SUCCESS;
}

enum driver_status driver_non_blocking_schedule(driver_t *driver, void* job) {
	
	if(driver->unqueue == 0){
		
		if(driver->close == 0){			//driver is closed, return CLOSED_ERR
			sem_post(&driver->mutex);
			return DRIVER_CLOSED_ERROR;
		}
		sem_wait(&driver->mutex);
		
		if(driver->handlequeue < 0){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_FULL;
		}
		else if (driver->handlequeue == 0){
			driver->handlequeue -- ;
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_FULL;
		}
		else{
			
		}
		if(sem_trywait(&driver->size)){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_FULL;
		}
		driver->isschedule = 1;
		sem_post(&driver->jobs);
		driver->job=job;
		driver->handlequeue -- ;
		sem_post(&driver->mutex);
		return SUCCESS;
		
	}
	else{
		if(driver->close == 0){			//driver is closed, return CLOSED_ERR
			sem_post(&driver->mutex);
			return DRIVER_CLOSED_ERROR;
		}
		sem_wait(&driver->mutex);
		enum queue_status qs;
		
		if(sem_trywait(&driver->size)){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_FULL;
		}
		qs= queue_add(driver->queue, job);
		if(qs == QUEUE_ERROR){			//queue error, return GEN_ERR
			sem_post(&driver->mutex);
			return DRIVER_GEN_ERROR;
		}
		sem_post(&driver->jobs);
		sem_post(&driver->mutex);//successful adding, return SUCCESS
		return SUCCESS;
	}
}

enum driver_status driver_non_blocking_handle(driver_t *driver, void **job) {
	
	if(driver->unqueue == 0){
		if(driver->close == 0){			//driver is closed, return CLOSED_ERR
				sem_post(&driver->mutex);
				return DRIVER_CLOSED_ERROR;
			}
		sem_wait(&driver->mutex);
		if(driver->handlequeue == 0){
			driver->handlequeue++;
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_EMPTY;
		}
		else if(driver->handlequeue > 0){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_EMPTY;
		}
	

			if(sem_trywait(&driver->jobs)){
				sem_post(&driver->mutex);
				return DRIVER_REQUEST_EMPTY;
			}
			*job = driver->job;
			driver->handlequeue++;
			sem_post(&driver->size);
			sem_post(&driver->mutex);					//successful removing, return SUCCESS
			
			return SUCCESS;
	}
	else{
		if(driver->close == 0){			//driver is closed, return CLOSED_ERR
			sem_post(&driver->mutex);
			return DRIVER_CLOSED_ERROR;
		}
		sem_wait(&driver->mutex);
		enum queue_status qs;
		
		if(sem_trywait(&driver->jobs)){
			sem_post(&driver->mutex);
			return DRIVER_REQUEST_EMPTY;
		}
		qs= queue_remove(driver->queue, job);
		if(qs == QUEUE_ERROR){			//queue error, return GEN_ERR
			sem_post(&driver->mutex);
			return DRIVER_GEN_ERROR;
		}
		sem_post(&driver->size);
		sem_post(&driver->mutex);					//successful removing, return SUCCESS
		return SUCCESS;
	}
}

enum driver_status driver_close(driver_t *driver) {
	sem_wait(&driver->mutex);
	if(driver->close == 0){		//if driver already closed
		sem_post(&driver->mutex);
		return DRIVER_GEN_ERROR;
	}
	else if(driver->close == 1){
		driver->close = 0;
		sem_post(&driver->size);
		sem_post(&driver->jobs);
		sem_post(&driver->mutex);
		return SUCCESS;
	}
	return DRIVER_GEN_ERROR;
	
}

enum driver_status driver_destroy(driver_t *driver) {
	if(driver->close == 1){
		return DRIVER_DESTROY_ERROR;
	}
	else if(driver->close == 0){
		sem_destroy(&driver->size);
		sem_destroy(&driver->jobs);
		sem_destroy(&driver->mutex);
		sem_destroy(&driver->handle);
		queue_free(driver->queue);
		free(driver);
		driver = NULL;
		return SUCCESS;
	}
	else{
		return DRIVER_GEN_ERROR;
	}
}

enum driver_status driver_select(select_t *driver_list, size_t driver_count, size_t* selected_index) {
	
	enum driver_status ds;
	sem_t select;
	sem_init(&select, 0, 0);

	while(1){
	for(int j=0; j<driver_count; j++){
		if(driver_list[j].op == SCHDLE){
			size_t count = 0;
			for(int i=0; i<driver_count;i++){
				sem_wait(&driver_list[i].driver->mutex);
				if(driver_list[i].driver->close == 0){
					sem_post(&driver_list[i].driver->mutex);
					*selected_index = count;					//sem_post(&driver_list[j].driver->mutex);
					return DRIVER_CLOSED_ERROR;
				}
				sem_post(&driver_list[i].driver->mutex);
				ds = driver_non_blocking_schedule(driver_list[i].driver, driver_list[i].job);
				sem_wait(&driver_list[i].driver->mutex);
				if(ds!=DRIVER_REQUEST_FULL){
					*selected_index = count;
					if(driver_list[j].driver == driver_list[i].driver){
						*selected_index = (size_t) j;
					}
					sem_post(&driver_list[i].driver->mutex);
					return ds;
				}
				sem_post(&driver_list[i].driver->mutex);
				count++;
			}
		}
		else if(driver_list[j].op == HANDLE){
			size_t count = 0;
			for(int i=0; i<driver_count; i++){
				sem_wait(&driver_list[i].driver->mutex);
				if(driver_list[i].driver->close == 0){
					*selected_index = count;
					sem_post(&driver_list[i].driver->mutex);
					return DRIVER_CLOSED_ERROR;
				}
				sem_post(&driver_list[i].driver->mutex);
				ds = driver_non_blocking_handle(driver_list[i].driver, &driver_list[i].job);
				sem_wait(&driver_list[i].driver->mutex);
				if(ds!=DRIVER_REQUEST_EMPTY){
					*selected_index = count;
					if(driver_list[j].driver == driver_list[i].driver){
						*selected_index = (size_t) j;
					}
					
					sem_post(&driver_list[i].driver->mutex);
					return ds;
				}
				sem_post(&driver_list[i].driver->mutex);
				count++;
			}
		}
		else{
			return DRIVER_GEN_ERROR;
		}
	}
	}
	return DRIVER_GEN_ERROR;
	

}

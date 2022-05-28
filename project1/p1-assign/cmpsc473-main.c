#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include "cmpsc473-kvs.h"
#include "cmpsc473-util.h"
#include "cmpsc473-format-156.h"   // CHANGE: student-specific

/* Defines */
#define OBJ_LEN     172  // CHANGE: size of object tree for this project
#define KEY_LEN     8
#define LINE_SIZE   100
#define INT_MIN     -1000
#define INT_MAX		1000

#define OBJECTS_PATH "./objects-file"

struct kvs *Objects;


/* Project APIs */
// public 
extern int set_object( char *objname,  char *filename );
extern int get_object( char *objname );

// internal
extern struct A *upload_A( FILE *fp );
extern struct B *upload_B( FILE *fp );
extern struct C *upload_C( FILE *fp );
extern unsigned char *marshall( struct A *objA );
extern struct A *unmarshall( unsigned char *obj );
extern int output_obj( struct A *objA );
extern int kvs_dump( struct kvs *kvs, char *filepath, unsigned int keysize, 
		     unsigned int valsize //, unsigned int tagsize
		     );

/*****************************

Invoke:
cmpsc473-p1 cmd obj-name obj-file

Commands:
<set_object> obj-name obj-file
<get_object> obj-name 

1 - set object - add object of <obj-name> from <obj-file> to object store

2 - get-object - retrieve object of <obj-name> from object store

******************************/
static inline int safe_atoi( char *str, int *tgt )
{
        char *end_ptr;
        int base = 10;
        // set errno = 0 before the call                                                                                         
        errno = 0;
        // same size in gcc - compile with -Wconversion                                                                          
        long num = strtol( str, &end_ptr, base );
        // error for converting to long                                                                                          
        if (((ERANGE == errno) && (( num == LONG_MAX ) || ( num == LONG_MIN )))
            || (( errno != 0 ) && ( num == 0 ))) {
                perror("strtol");
                return -1;
        }
        else if (end_ptr == str) {
                if (puts("not valid numeric input\n") == EOF) {
                        /* Handle error */
                }
                return -1;
        }
        else if ('\n' != *end_ptr && '\0' != *end_ptr) {
                if (puts("extra characters on input line\n") == EOF) {
                        /* Handle error */
                }
                return -1;
        }
 
        // bigger than int?                                                                                                      
        else if (( num >= INT_MAX ) || ( num <= INT_MIN )) {
                if (puts("too big for int\n") == EOF) {
                        tgt=0;
                }
                return -1;
        }
        *tgt = num;    // long to int here                                                                                       
        return 0;  // means OK, tgt has value                                                                                    
}


int main( int argc, char *argv[] )
{
	int rtn;

	assert( argc >= 3 );

	/* initialize KVS from file */
	Objects = (struct kvs *)malloc(sizeof(struct kvs));
	kvs_init( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN //, PAD_LEN 
		  );  // OBJ_LEN - size of the object tree for this project

	if ( strncmp( argv[1], "set", 1 ) == 0 ) {
		assert( argc == 4 );
		rtn = set_object( argv[2], argv[3] );
	}
	else if ( strncmp( argv[1], "get", 2 ) == 0 ) {
		assert( argc == 3 );
		rtn = get_object( argv[2] );
	}
	else {
		printf( "Unknown command: %s\nExiting...\n", argv[1] );
		exit(-1);
	}

	kvs_dump( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN ); 

	exit(0);
}


int get_object( char *objname )
{
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *obj;
	int rc;

	struct A *objA;

	assert( strlen(objname) <= KEY_LEN );  

	memset( key, 0, KEY_LEN );
	memcpy( key, objname, strlen(objname) );

	rc = kvs_auth_get( Objects, key, &obj );
 
	if ( rc == 0 ) {  // found object, run op0 (output)
		objA = unmarshall( obj );
		//printf("Object Retrieved: %s\n", key );
		
		objA->op0( objA );
	}
	else {
		fprintf(stderr, "get_object failed to return object for name: %s\n", objname );
		return -1;
	}

	return 0;
}


int set_object( char *objname, char *filename )
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0, size;
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	struct A *objA;
	struct B *objB;
	struct C *objC;

	fp = fopen( filename, "r" );  // read input
	assert( fp != NULL ); 

	memset( key, 0, KEY_LEN );
	memcpy( key, objname, strlen(objname) );

	fp = fopen( filename, "r" );  // read input
	assert( fp != NULL ); 

	while(1) {
		size = getline( &line, &len, fp );
		if ( size == -1 ) break;

		if ( strcmp( line, "struct A\n" ) == 0 ) {
			objA = upload_A( fp );
			if (!objA) return -1;
		}

		else if ( strcmp( line, "struct B\n" ) == 0 ) {
			objB = upload_B( fp );
			if (!objB) return -1;
		}

		else if ( strcmp( line, "struct C\n" ) == 0 ) {
			objC = upload_C( fp );
			if (!objC) return -1;
		}
	}

	// TASK 2: 
	// update pointers from objA to other objects 
	// assign objA function pointers
	objA->ptr_e=objC;
	objA->ptr_b=objB;
	objA->op0=&output_obj;
	objA->op1=&marshall;
	/* upload object into key-value store */
	// Run op1 (marshall)
	kvs_auth_set( Objects, key, objA->op1(objA) );

	return 0;
}


// TASK 1: Upload object specific data into fields of objects
// See example below for objD 
struct A *upload_A( FILE *fp)
{
	char *line=NULL;
	size_t len = 0, size;
	struct A *objA = (struct A *)malloc(sizeof(struct A));

	/* parse and set objA field values */
	memset(objA, 0, sizeof(struct A));
	while(1){
	  size=getline(&line, &len, fp);
	  if( strncmp(line, "\n", 1) == 0){
		break;
	  }
	  //if(len>100){
	//	printf("line is too long to be inserted"); 			//check if line length valid
	//	continue;
	//  }
	  line[strlen(line)-1]='\0';
	  if((line[6] == 'n')||(line[6] == 'p')){
		char *type = strstr(line, "num_f");
		if(type!=NULL){
		  int num;
		  safe_atoi(type+6, &num);
		  objA->num_f=num;
		}
		else if((type=strstr(line, "ptr_e"))!=NULL){
			continue;
		  /*if(type[6]=='C'){
			objA->ptr_e=objC;
		  }
		  else{
			printf("invalid pointer name");  				//check if pointer name valid
		  }*/
		}
		else if((type=strstr(line, "ptr_b"))!=NULL){
			continue;
		  /*if(type[6]=='B'){
			objA->ptr_b=objB;  
		  }
		  else{
			printf("invalid pointer name");  
		  }*/
		}
		else{
		  printf("invalid data type2");						//check if data type valid
		  continue;
		}
	  }
	  else if(line[6] == 's'){
		char *type=strstr(line, "string_a");
		if(type!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objA->string_a),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");  			//check if string length valid
			memcpy(&(objA->string_a),type+9, STRLEN);
		  }
		}
		else if((type=strstr(line, "string_c"))!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objA->string_c),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");
			memcpy(&(objA->string_c),type+9, STRLEN);			
		  }	
		}
		else if((type=strstr(line, "string_d"))!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objA->string_d),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");  
			memcpy(&(objA->string_d),type+9, STRLEN);
		  }	
		}
		else{
		  printf("invalid data type3");
		}
	  }
	  else{
		printf("invalid data type1");
		continue;
	  }
	}

	return objA;
}



struct B *upload_B( FILE *fp )
{
	char *line=NULL;
	size_t len = 0, size;
	struct B *objB = (struct B *)malloc(sizeof(struct B));

	/* parse and set objB field values */
	memset(objB, 0, sizeof(struct B));
	while(1){
	  size=getline(&line, &len, fp);
	  if( strncmp(line, "\n", 1) == 0){
		break;
	  }
	  /*if(len>100){
		printf("line is too long to be inserted"); 			//check if line length valid
		continue;
	  }*/
	  line[strlen(line)-1]='\0';
	  if(line[6] == 'n'){
		char *type = strstr(line, "num_e");
		if(type!=NULL){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objB->num_e=num;
		}
		else if(type=strstr(line, "num_b")){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objB->num_b=num;	
		}
		else if(type=strstr(line, "num_a")){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objB->num_a=num;	
		}
		else{
		  printf("invalid data type4");						//check if data type valid
		  continue;
		}
	  }
	  else if(line[6] == 's'){
		char *type=strstr(line, "string_c");
		if(type!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objB->string_c),type+9, strlen(type+8));
		  }
		  else{
			type[STRLEN+8]='\0';
			printf("string invalid{too long)"); 			//check if string length valid
			memcpy(&(objB->string_c),type+9, STRLEN);
		  }
		}
		
		else if((type=strstr(line, "string_d"))!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objB->string_d),type+9, strlen(type+8));
		  }
		  else{
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");  
			memcpy(&(objB->string_d),type+9, STRLEN);
		  }	
		}
		else{
		  printf("invalid data type5");
		}
	  }
	  else{
		printf("invalid data type6");
		continue;
	  }
	}

	return objB;
}


struct C *upload_C( FILE *fp )
{
	char *line=NULL;
	size_t len = 0, size;
	struct C *objC = (struct C *)malloc(sizeof(struct C));

	/* parse and set objC field values */
	memset(objC, 0, sizeof(struct C));
	while(1){
	  size=getline(&line, &len, fp);
	  if( strncmp(line, "\n", 1) == 0){
		break;
	  }
	  /*if(len>100){
		printf("line is too long to be inserted"); 			//check if line length valid
		continue;
	  }*/
	  line[strlen(line)-1]='\0';
	  if(line[6] == 'n'){
		char *type = strstr(line, "num_e");
		if(type!=NULL){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objC->num_e=num;
		}
		else if(type=strstr(line, "num_c")){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objC->num_c=num;	
		}
		else if(type=strstr(line, "num_a")){
		  int num=NULL;
		  safe_atoi(type+6, &num);
		  objC->num_a=num;	
		}
		else{
		  printf("invalid data type7");
		  continue;
		}
	  }
	  else if(line[6] == 's'){
		char *type=strstr(line, "string_b");
		if(type!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objC->string_b),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");  			//check if string length valid
			memcpy(&(objC->string_b),type+9, STRLEN);
		  }
		}
		else if((type=strstr(line, "string_d"))!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objC->string_d),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)");  
			memcpy(&(objC->string_d),type+9, STRLEN);
		  }	
		}
		else if((type=strstr(line, "string_f"))!=NULL){
		  if(strlen(type+9)<(STRLEN+1)){
			memcpy(&(objC->string_f),type+9, strlen(type+8));
		  }
		  else{
			  
			type[STRLEN+8]='\0';
			printf("string invalid{too long)"); 
			memcpy(&(objC->string_f),type+9, STRLEN);
		  }	
		}
		else{
		  printf("invalid data type8");
		  continue;
		}
	  }
	  else{
		printf("invalid data type1");
		continue;
	  }
	}

	return objC;
}


/*  Example 
struct D *upload_D( FILE *fp )
{
        char *line = NULL;
	// other declarations
	struct D *objD = (struct D *)malloc(sizeof(struct D));
	memset( objD, 0, sizeof(struct D) );

	while(1) {
		size = getline( &line, &len, fp );
		if ( strncmp( line, "\n", 1 ) == 0 )
			break;
       
                // replace \n at end with null-terminator for value
		line[strlen(line)-1] = '\0';   

		if (( ref = strstr( line, "num_a" ))) {
			objD->num_a = atoi( ref+6 );
		}

		if (( ref = strstr( line, "string_b" ))) {
			memcpy( &(objD->string_b), ref+9, strlen(ref+9) );
		}
	}


	return objD;
}
*/


// TASK 3: Linearize data for objects A, B, and C
// suitable for storing the objects in the key-value store and on-disk
unsigned char *marshall( struct A *objA )
{
	unsigned char *obj = (unsigned char *)malloc(OBJ_LEN);
	struct B *objB=objA->ptr_b;
	struct C *objC=objA->ptr_e;
	
	
	memcpy( obj, &(objA->string_a), STRLEN );
	memcpy( obj+STRLEN, &(objB->num_a), sizeof(int) );
	memcpy( obj+STRLEN+sizeof(int), &(objB->num_b), sizeof(int) ); 
	memcpy( obj+(2*sizeof(int))+STRLEN, &(objB->string_c), STRLEN);
	memcpy( obj+(2*sizeof(int))+(2*STRLEN), &(objB->string_d), STRLEN );
	memcpy( obj+(2*sizeof(int))+(3*STRLEN), &(objB->num_e), sizeof(int) );
	memcpy( obj+(3*sizeof(int))+(3*STRLEN), &(objA->string_c), STRLEN );
	memcpy( obj+(3*sizeof(int))+(4*STRLEN), &(objA->string_d), STRLEN );
	memcpy( obj+(3*sizeof(int))+(5*STRLEN), &(objC->num_a), sizeof(int) );
	memcpy( obj+(4*sizeof(int))+(5*STRLEN), &(objC->string_b), STRLEN );
	memcpy( obj+(4*sizeof(int))+(6*STRLEN), &(objC->num_c), sizeof(int) );
	memcpy( obj+(5*sizeof(int))+(6*STRLEN), &(objC->string_d), STRLEN );
	memcpy( obj+(5*sizeof(int))+(7*STRLEN), &(objC->num_e), sizeof(int) );
	memcpy( obj+(6*sizeof(int))+(7*STRLEN), &(objC->string_f), STRLEN );
	memcpy( obj+(6*sizeof(int))+(8*STRLEN), &(objA->num_f), sizeof(int) );
	

	// Append each field value in order at end of buffer
	// Extend on example below

	printf("Size of object = %lu\n", 
	       sizeof(int)+3*STRLEN+
	       // sizeof A's fields that need to be stored - non-pointers
	       +sizeof(struct B)+sizeof(struct C));
 
	return obj;
}

/* 

   Example:

	memcpy( obj, &(objA->num_a), sizeof(int) );
	memcpy( obj+sizeof(int), &(objA->num_b), sizeof(int) );
	memcpy( obj+(2*sizeof(int)), &(objA->string_c), STRLEN ); 
	memcpy( obj+(2*sizeof(int))+STRLEN, &(objA->string_d), STRLEN ); 
	...

*/



// TASK 4: Convert linear layout of object data to structured layout
// Assign each element in the buffer to its field
struct A *unmarshall( unsigned char *obj )
{
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	struct C *objC = (struct C *)malloc(sizeof(struct C));
	
	memcpy( &(objA->string_a), obj, STRLEN );
	memcpy( &(objB->num_a), obj+STRLEN, sizeof(int) );
	memcpy( &(objB->num_b), obj+STRLEN+sizeof(int), sizeof(int) ); 
	memcpy( &(objB->string_c), obj+(2*sizeof(int))+STRLEN, STRLEN );
	memcpy( &(objB->string_d), (obj+(2*sizeof(int))+(2*STRLEN)), STRLEN );
	memcpy( &(objB->num_e), (obj+(2*sizeof(int))+(3*STRLEN)), sizeof(int) );
	memcpy( &(objA->string_c), (obj+(3*sizeof(int))+(3*STRLEN)), STRLEN );
	memcpy( &(objA->string_d), (obj+(3*sizeof(int))+(4*STRLEN)), STRLEN );
	memcpy( &(objC->num_a), (obj+(3*sizeof(int))+(5*STRLEN)), sizeof(int) );
	memcpy( &(objC->string_b), (obj+(4*sizeof(int))+(5*STRLEN)), STRLEN );
	memcpy( &(objC->num_c), (obj+(4*sizeof(int))+(6*STRLEN)), sizeof(int) );
	memcpy( &(objC->string_d), (obj+(5*sizeof(int))+(6*STRLEN)), STRLEN );
	memcpy( &(objC->num_e), (obj+(5*sizeof(int))+(7*STRLEN)), sizeof(int) );
	memcpy( &(objC->string_f), (obj+(6*sizeof(int))+(7*STRLEN)), STRLEN );
	memcpy( &(objA->num_f), (obj+(6*sizeof(int))+(8*STRLEN)), sizeof(int) );
	// find and assign field values for A, B, and C

	objA->ptr_b = objB;
	objA->ptr_e = objC;
	
	objA->op0=&output_obj;
	objA->op1=&marshall;

	// assign function pointers

	return objA;
}


// TASK 5: Output first 4 fields of A, B, and C as output
// Fix to match your structures
// Example below
int output_obj( struct A *objA )
{
	// Base object fields
	printf("ObjA\n");
	printf("ObjA -> num_f: %d\n", objA->num_f );

	// First sub-object fields
	printf("ObjB\n");
	printf("ObjB -> num_a: %d\n", objA->ptr_b->num_a );
	printf("ObjB -> num_b: %d\n", objA->ptr_b->num_b );
	printf("ObjB -> string_c: %s\n", objA->ptr_b->string_c );
	printf("ObjB -> string_d: %s\n", objA->ptr_b->string_d );
	printf("ObjB -> num_e: %d\n", objA->ptr_b->num_e );

	// Last sub-object fields
	printf("ObjC\n");
	printf("ObjC -> num_a: %d\n", objA->ptr_e->num_a );
	printf("ObjC -> string_b: %s\n", objA->ptr_e->string_b );
	printf("ObjC -> num_c: %d\n", objA->ptr_e->num_c );
	printf("ObjC -> string_d: %s\n", objA->ptr_e->string_d );
	printf("ObjC -> num_e: %d\n", objA->ptr_e->num_e );
	printf("ObjC -> string_f: %s\n", objA->ptr_e->string_f );

	return 0;
}


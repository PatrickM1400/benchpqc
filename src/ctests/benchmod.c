#include <stdio.h>
#include <stdlib.h>

#include "papi.h"
#include "papi_test.h"

#include "oqs/oqs.h"

#include "testcode.h"


int main(){
	int retval;

	retval=PAPI_library_init(PAPI_VER_CURRENT);
	if (retval!=PAPI_VER_CURRENT) {
		fprintf(stderr,"Error initializing PAPI! %s\n",
				PAPI_strerror(retval));
		return 0;
	}
	printf("PAPI Initialized!\n");
	int eventset=PAPI_NULL;

	retval=PAPI_create_eventset(&eventset);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error creating eventset! %s\n",
				PAPI_strerror(retval));
	}
	printf("Eventset created\n");
	retval=PAPI_add_named_event(eventset,"PAPI_TOT_CYC");
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error adding PAPI_TOT_CYC: %s\n",
				PAPI_strerror(retval));
	}
	printf("Added PAPI_TOT_CYC\n");
	// volatile int a = 19123747;
	volatile int a = 1<<8;
	volatile int b = 173492834;

	long long count;

	PAPI_reset(eventset);
	retval=PAPI_start(eventset);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error starting count: %s\n",
				PAPI_strerror(retval));
	}
	
	for(int i = 0; i < 100000; i++){
		volatile int c = b%a;
	}
		// printf("Floating Point Divison Result: %d\n", b%a);

	retval=PAPI_stop(eventset,&count);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error stopping:  %s\n",
				PAPI_strerror(retval));
	}
	else {
		printf("Measured %lld cycles\n",count);
		printf("Measured average: %lld.%5lld\n", count/100000, count%100000);
	}
}

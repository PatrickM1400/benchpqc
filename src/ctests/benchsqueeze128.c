#include <stdio.h>
#include <stdlib.h>

#include "papi.h"
#include "papi_test.h"

#include "oqs/oqs.h"

#include "testcode.h"
#include "oqs/sha3.h"
#include "oqs/rand.h"

#define SEEDBYTES 32
#define CRHBYTES 64
#define K 4
#define L 4

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

	uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
	OQS_randombytes(seedbuf, SEEDBYTES);
	seedbuf[SEEDBYTES+0] = K;
	seedbuf[SEEDBYTES+1] = L;
	long long count;

	PAPI_reset(eventset);
	retval=PAPI_start(eventset);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error starting count: %s\n",
				PAPI_strerror(retval));
	}
	
	OQS_SHA3_shake128(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);

	retval=PAPI_stop(eventset,&count);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error stopping:  %s\n",
				PAPI_strerror(retval));
	}
	else {
		printf("Measured %lld cycles\n",count);
	}
}

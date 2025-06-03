/* Set up to run ML-DSA with security strength 3 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "papi.h"
#include "papi_test.h"

#include "oqs/oqs.h"

#define NUMBER_TRIALS 1

static void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, OQS_SIG *sig);

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}

int main(){
	int retval;

	retval=PAPI_library_init(PAPI_VER_CURRENT);
	if (retval!=PAPI_VER_CURRENT) {
		fprintf(stderr,"Error initializing PAPI! %s\n",
				PAPI_strerror(retval));
		return 0;
	}
	// printf("PAPI Initialized!\n");
	int eventset=PAPI_NULL;

	retval=PAPI_create_eventset(&eventset);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error creating eventset! %s\n",
				PAPI_strerror(retval));
		exit(1);
	}

	// int numEvents = 5;
	// char* eventNames[] = {"PAPI_TOT_CYC", "PAPI_MEM_WCY ", "PAPI_LST_INS", \
	// 					"PAPI_L2_TCA", "PAPI_L3_TCA"};

	int numEvents = 1;
	char *eventNames[] = {"PAPI_L2_TCM"};

	// printf("Eventset created\n");

	for (int i = 0; i < numEvents; ++i) {
		retval=PAPI_add_named_event(eventset, eventNames[i]);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error adding %s: %s\n",
					eventNames[i], PAPI_strerror(retval));
		}
	}

	// printf("\n");

	long long int KeyGenCount[numEvents];
	long long int SignCount[numEvents];
	long long int VerifyCount[numEvents];

	long long int KeyGenTotal[numEvents];
	long long int SignTotal[numEvents];
	long long int VerifyTotal[numEvents];
	
	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

	const uint8_t *message = "test";
	const char *algorithm = OQS_SIG_alg_ml_dsa_65;



	for (int i = 1; i <= NUMBER_TRIALS; ++i) {

		// if (i % (NUMBER_TRIALS/10) == 0) printf("On trial %d\n", i);

		sig = OQS_SIG_new(algorithm);
		if (sig == NULL) {
			printf("%s was not enabled at compile-time.\n", algorithm);
			return OQS_ERROR;
		}

		public_key = malloc(sig->length_public_key);
		secret_key = malloc(sig->length_secret_key);
		signature = malloc(sig->length_signature);

		if ((public_key == NULL) || (secret_key == NULL)|| (signature == NULL)) {
			fprintf(stderr, "ERROR: malloc failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		PAPI_reset(eventset);
		retval=PAPI_start(eventset);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error starting count: %s\n",
					PAPI_strerror(retval));
		}

		rc = OQS_SIG_keypair(sig, public_key, secret_key);

		retval=PAPI_stop(eventset, KeyGenCount);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error stopping:  %s\n",
					PAPI_strerror(retval));
		}

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		PAPI_reset(eventset);
		retval=PAPI_start(eventset);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error starting count: %s\n",
					PAPI_strerror(retval));
		}

		rc = OQS_SIG_sign(sig, signature, &signature_len, message, strlen(message), secret_key);

		retval=PAPI_stop(eventset, SignCount);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error stopping:  %s\n",
					PAPI_strerror(retval));
		}

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		PAPI_reset(eventset);
		retval=PAPI_start(eventset);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error starting count: %s\n",
					PAPI_strerror(retval));
		}

		rc = OQS_SIG_verify(sig, message, strlen(message), signature, signature_len, public_key);

		retval=PAPI_stop(eventset, VerifyCount);
		if (retval!=PAPI_OK) {
			fprintf(stderr,"Error stopping:  %s\n",
					PAPI_strerror(retval));
		}

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			exit(1);
		}

		cleanup_heap(public_key, secret_key, signature, sig);


		for (int j = 0; j < numEvents; ++j) {
			KeyGenTotal[j] += KeyGenCount[j];
			SignTotal[j] += SignCount[j];
			VerifyTotal[j] += VerifyCount[j];
		}
	}

	for (int j = 0; j < numEvents; ++j) {
		KeyGenTotal[j] = KeyGenTotal[j] / NUMBER_TRIALS;
		SignTotal[j] = SignTotal[j] / NUMBER_TRIALS;
		VerifyTotal[j] = VerifyTotal[j] / NUMBER_TRIALS;
	}

	// for (int i = 0; i < numEvents; ++i) {
	// 	printf("Measured %lld for %s KeyGen\n", KeyGenTotal[i], eventNames[i]);
	// }
	// printf("\n");
	// for (int i = 0; i < numEvents; ++i) {
	// 	printf("Measured %lld for %s Sign\n", SignTotal[i], eventNames[i]);
	// }
	// printf("\n");
	// for (int i = 0; i < numEvents; ++i) {
	// 	printf("Measured %lld for %s Verify\n", VerifyTotal[i], eventNames[i]);
	// }

	FILE *pFile;

	pFile = fopen("benchgen.txt", "a");
	if(pFile==NULL) {
		perror("Error opening file.");
	}
	else {
		char *buff;
		if(0 > asprintf(&buff, "%lli,%lli,%lli\n", KeyGenTotal[0], SignTotal[0], VerifyTotal[0])) return -1;
		fputs(buff, pFile);
		free(buff);
	}	
	fclose(pFile);

}

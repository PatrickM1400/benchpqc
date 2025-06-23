/* Set up to run ML-DSA with security strength 2 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "papi.h"
#include <sys/time.h>
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

	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

	const uint8_t *message = "test";
	// const char *algorithm = OQS_SIG_alg_ml_dsa_44;
	const char *algorithm = OQS_SIG_alg_ml_dsa_65;
	// const char *algorithm = OQS_SIG_alg_ml_dsa_87;

	for (int i = 1; i <= NUMBER_TRIALS; ++i) {

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

		long long startUsec, endUsec;
		long long timeKeyGen, timeSign, timeVerify;
		timeKeyGen = 0;
		timeSign = 0;
		timeVerify = 0;
		struct timeval startTime, endTime;

		gettimeofday(&startTime, NULL);
		rc = OQS_SIG_keypair(sig, public_key, secret_key);
		gettimeofday(&endTime, NULL);

		startUsec = startTime.tv_sec * 1000000 + startTime.tv_usec;
		endUsec = endTime.tv_sec * 1000000 + endTime.tv_usec;
		timeKeyGen = endUsec - startUsec;
		// printf("KeyGen time: %lld\n", endUsec - startUsec);

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		gettimeofday(&startTime, NULL);
		rc = OQS_SIG_sign(sig, signature, &signature_len, message, strlen(message), secret_key);
		gettimeofday(&endTime, NULL);

		startUsec = startTime.tv_sec * 1000000 + startTime.tv_usec;
		endUsec = endTime.tv_sec * 1000000 + endTime.tv_usec;
		timeSign = endUsec - startUsec;
		// printf("Sign time: %lld\n", endUsec - startUsec);

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		gettimeofday(&startTime, NULL);
		rc = OQS_SIG_verify(sig, message, strlen(message), signature, signature_len, public_key);
		gettimeofday(&endTime, NULL);

		startUsec = startTime.tv_sec * 1000000 + startTime.tv_usec;
		endUsec = endTime.tv_sec * 1000000 + endTime.tv_usec;
		timeVerify = endUsec - startUsec;
		// printf("Verify time: %lld\n", endUsec - startUsec);

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			exit(1);
		}

		cleanup_heap(public_key, secret_key, signature, sig);

		FILE *pFile;

		pFile = fopen("benchtime.txt", "a");
		if(pFile==NULL) {
			perror("Error opening file.");
		}
		else {
			char *buff;
			if(0 > asprintf(&buff, "%lli,%lli,%lli\n", timeKeyGen, timeSign, timeVerify)) return -1;
			fputs(buff, pFile);
			free(buff);
		}	
		fclose(pFile);
	}
}

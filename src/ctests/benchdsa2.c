#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "papi.h"
#include "papi_test.h"

#include "oqs.h"

#include "testcode.h"

static void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, OQS_SIG *sig);

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature,
                  OQS_SIG *sig) {
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

	long long KeyGenCount;
	long long SignCount;
	long long VerifyCount;
	
	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

	const uint8_t *message = "test";

	// fuzz_ctx_t ctx = init_fuzz_context(data, data_len);

	const char *algorithm = OQS_SIG_alg_ml_dsa_44;

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

	retval=PAPI_stop(eventset,&KeyGenCount);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error stopping:  %s\n",
				PAPI_strerror(retval));
	}
	else {
		printf("Measured %lld cycles for KeyGen\n",KeyGenCount);
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

	retval=PAPI_stop(eventset,&SignCount);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error stopping:  %s\n",
				PAPI_strerror(retval));
	}
	else {
		printf("Measured %lld cycles for Sign\n",SignCount);
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

	retval=PAPI_stop(eventset,&VerifyCount);
	if (retval!=PAPI_OK) {
		fprintf(stderr,"Error stopping:  %s\n",
				PAPI_strerror(retval));
	}
	else {
		printf("Measured %lld cycles for Verify\n",VerifyCount);
	}

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
		cleanup_heap(public_key, secret_key, signature, sig);
		exit(1);
	}

	cleanup_heap(public_key, secret_key, signature, sig);
	// return OQS_SUCCESS; // TODO: Check for success




}

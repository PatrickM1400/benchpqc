/* Set up to run ML-DSA with security strength 2 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

	const uint8_t *message = "test";
	const char *algorithm = OQS_SIG_alg_ml_dsa_44;
	//const char *algorithm = OQS_SIG_alg_ml_dsa_65;
	//const char *algorithm = OQS_SIG_alg_ml_dsa_87;

	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

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

	rc = OQS_SIG_keypair(sig, public_key, secret_key);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
		cleanup_heap(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}

	for(int i = 0; i < sig->length_public_key; ++i) {
		printf("%02x", public_key[i]);
	}
	printf("\n");

	for(int i = 0; i < sig->length_secret_key; ++i) {
		printf("%02x", secret_key[i]);
	}
	printf("\n");

	rc = OQS_SIG_sign(sig, signature, &signature_len, message, strlen(message), secret_key);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
		cleanup_heap(public_key, secret_key, signature, sig);
		return OQS_ERROR;
	}

	rc = OQS_SIG_verify(sig, message, strlen(message), signature, signature_len, public_key);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
		cleanup_heap(public_key, secret_key, signature, sig);
		exit(1);
	}

	cleanup_heap(public_key, secret_key, signature, sig);
}

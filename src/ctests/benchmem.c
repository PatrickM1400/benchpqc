/* Set up to run ML-DSA with security strength 2 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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

	const uint8_t *message = "test";
	const char *algorithm = OQS_SIG_alg_ml_dsa_44;
	// const char *algorithm = OQS_SIG_alg_ml_dsa_65;
	// const char *algorithm = OQS_SIG_alg_ml_dsa_87;

	
	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;


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

		// printf("Public Key Size: %d\n", sig->length_public_key);
		// printf("Secret Key Size: %d\n", sig->length_secret_key);
		// printf("Signature Size: %d\n", sig->length_signature);

		if ((public_key == NULL) || (secret_key == NULL)|| (signature == NULL)) {
			fprintf(stderr, "ERROR: malloc failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			return OQS_ERROR;
		}

		FILE *pFile;

		pFile = fopen("public_key.txt", "r");
		if(pFile==NULL) {
			perror("Error opening file.");
		} else {
			fread(public_key, sizeof(uint8_t), sig->length_public_key, pFile);
		}	
		fclose(pFile);

		pFile = fopen("secret_key.txt", "r");
		if(pFile==NULL) {
			perror("Error opening file.");
		} else {
			fread(secret_key, sizeof(uint8_t), sig->length_secret_key, pFile);
		}	
		fclose(pFile);

		// rc = OQS_SIG_keypair(sig, public_key, secret_key);

		// if (rc != OQS_SUCCESS) {
		// 	fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
		// 	cleanup_heap(public_key, secret_key, signature, sig);
		// 	return OQS_ERROR;
		// }

		// pFile = fopen("public_key.txt", "w");
		// if(pFile==NULL) {
		// 	perror("Error opening file.");
		// } else {
		// 	fwrite(public_key, sizeof(uint8_t), sig->length_public_key, pFile);
		// }	
		// fclose(pFile);

		// pFile = fopen("secret_key.txt", "w");
		// if(pFile==NULL) {
		// 	perror("Error opening file.");
		// } else {
		// 	fwrite(secret_key, sizeof(uint8_t), sig->length_secret_key, pFile);
		// }	
		// fclose(pFile);

		// rc = OQS_SIG_sign(sig, signature, &signature_len, message, strlen(message), secret_key);

		// if (rc != OQS_SUCCESS) {
		// 	fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
		// 	cleanup_heap(public_key, secret_key, signature, sig);
		// 	return OQS_ERROR;
		// }

		// pFile = fopen("signature.txt", "w");
		// if(pFile==NULL) {
		// 	perror("Error opening file.");
		// } else {
		// 	fwrite(signature, sizeof(uint8_t), sig->length_signature, pFile);
		// }	
		// fclose(pFile);

		pFile = fopen("signature.txt", "r");
		if(pFile==NULL) {
			perror("Error opening file.");
		} else {
			fread(signature, sizeof(uint8_t), sig->length_signature, pFile);
		}	
		fclose(pFile);


		rc = OQS_SIG_verify(sig, message, strlen(message), signature, sig->length_signature, public_key);

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
			cleanup_heap(public_key, secret_key, signature, sig);
			exit(1);
		}

		// FILE *pFile;

		// pFile = fopen("public_key.txt", "w");
		// if(pFile==NULL) {
		// 	perror("Error opening file.");
		// } else {
		// 	fwrite(public_key, sizeof(uint8_t), sig->length_public_key, pFile);
		// }	
		// fclose(pFile);

		// pFile = fopen("secret_key.txt", "w");
		// if(pFile==NULL) {
		// 	perror("Error opening file.");
		// } else {
		// 	fwrite(secret_key, sizeof(uint8_t), sig->length_secret_key, pFile);
		// }	
		// fclose(pFile);

		cleanup_heap(public_key, secret_key, signature, sig);

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

	// FILE *pFile;

	// pFile = fopen("benchgen.txt", "a");
	// if(pFile==NULL) {
	// 	perror("Error opening file.");
	// }
	// else {
	// 	char *buff;
	// 	if(0 > asprintf(&buff, "%lli,%lli,%lli\n", KeyGenTotal[0], SignTotal[0], VerifyTotal[0])) return -1;
	// 	fputs(buff, pFile);
	// 	free(buff);
	// }	
	// fclose(pFile);
	return 0;
}

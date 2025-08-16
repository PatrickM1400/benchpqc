#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/decoder.h>

#define KEYGEN 1
#define SIGNATURE 2
#define VERIFY 3

const unsigned char public_key[] = "-----BEGIN PUBLIC KEY-----\n"
                        "MCowBQYDK2VwAyEAYm56KN7AhchqONPCKUka3smz8I718vyoBM7CRZzAt/4=\n"
                        "-----END PUBLIC KEY-----";

const unsigned char private_key[] = "-----BEGIN PRIVATE KEY-----\n"
                        "MC4CAQAwBQYDK2VwBCIEIAKen/k3pPXdCNCQZEmd2Bu16wPzex3HQxWcKdLwBo29\n"
                        "-----END PRIVATE KEY-----";

 unsigned char signature[64] = {0x7f,0xdb,0x5d,0x8a,0x41,0x22,0xa1,0x24,0x56,0xb1,0x29,0xfe,0xf0,0x24,0x36,0xa9,0x44,0x26,0x8f,0xbf,0x81,0x3a,0x9f,0x70,0x56,0x7b,0x89,0xd7,0xbc,0xaf,0xad,0xc4,0x89,0x92,0x6b,0x53,0x09,0x18,0xd4,0x70,0x4c,0x54,0x92,0x0f,0xae,0x94,0x7b,0xab,0xaf,0x96,0x4f,0x4e,0x05,0x57,0x63,0x94,0x5f,0xa3,0x91,0x47,0xbe,0x05,0x11,0x07};

// Function to handle OpenSSL errors
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {

    if (argc != 2){
		printf("Invalid number of command line arguments\n");
		printf("./bench_ed25519 <CRYPTO_OPERATION>");
		return -1;
    }

	char * cryptoArg = argv[1]; // 1 - KeyGen, 2 - Signature, 3 - Verify
	int cryptoInt = atoi(cryptoArg);

	switch(cryptoInt) {
		case KEYGEN:
		case SIGNATURE:
		case VERIFY:
			break;
		default:
			printf("Invalid crypto mode selected\n");
			return -1;
	}

    switch(cryptoInt) {
    case KEYGEN:
            // --- 1. Key Generation ---
            // This section generates a new Ed25519 key pair.
            EVP_PKEY *pkey = NULL;
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
            if (!pctx) {
                fprintf(stderr, "Failed to create EVP_PKEY_CTX.\n");
                handle_errors();
            }

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                fprintf(stderr, "Failed to initialize keygen.\n");
                handle_errors();
            }

            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                fprintf(stderr, "Failed to generate key.\n");
                handle_errors();
            }

            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            break;
        case SIGNATURE:
            // --- 2. Signing ---
            // This section signs a message using the generated private key.
            // Note: For Ed25519, the hash function is intrinsic to the algorithm,
            // so we pass NULL for the message digest type in EVP_DigestSignInit.
            EVP_MD_CTX *mdctx_sign = EVP_MD_CTX_new();
            if (!mdctx_sign) {
                fprintf(stderr, "Failed to create signing context.\n");
                handle_errors();
            }

            // The message to be signed
            const char msg[] = "This is the string we want to sign.";
            size_t msg_len = strlen(msg);
            unsigned char *sig = NULL;
            size_t sig_len;

            const unsigned char *key_signature = private_key;
            size_t key_length_signature = strlen(private_key);

            OSSL_DECODER_CTX* dctx_signature;
            EVP_PKEY* pkey_signatuare = NULL;

            dctx_signature = OSSL_DECODER_CTX_new_for_pkey(&pkey_signatuare, "PEM", NULL, "ED25519", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
            if (dctx_signature == NULL) {
                fprintf(stderr, "Failed to create decoder context\n");
                handle_errors();
            }

            if (!OSSL_DECODER_from_data(dctx_signature, &key_signature, &key_length_signature)) {
                fprintf(stderr, "Failed to import private key\n");
                handle_errors();
            }

            // Initialize the signing operation
            if (EVP_DigestSignInit(mdctx_sign, NULL, NULL, NULL, pkey_signatuare) <= 0) {
                fprintf(stderr, "Failed to initialize digest signing.\n");
                handle_errors();
            }

            // This is a one-shot signing function that handles hashing and signing.
            // First, determine the required buffer size for the signature.
            if (EVP_DigestSign(mdctx_sign, NULL, &sig_len, (const unsigned char *)msg, msg_len) <= 0) {
                fprintf(stderr, "Failed to determine signature length.\n");
                handle_errors();
            }

            // Allocate memory for the signature
            sig = OPENSSL_malloc(sig_len);
            if (!sig) {
                fprintf(stderr, "Failed to allocate memory for signature.\n");
                handle_errors();
            }

            // Perform the actual signing
            if (EVP_DigestSign(mdctx_sign, sig, &sig_len, (const unsigned char *)msg, msg_len) <= 0) {
                fprintf(stderr, "Failed to perform signing.\n");
                handle_errors();
            }
            
 
            EVP_MD_CTX_free(mdctx_sign);
            OSSL_DECODER_CTX_free(dctx_signature);
            OPENSSL_free(sig);
            break;
        case VERIFY:
            // --- 3. Verification ---
            // This section verifies the signature against the original message
            // using the public key.
            EVP_MD_CTX *mdctx_verify = EVP_MD_CTX_new();
            if (!mdctx_verify) {
                fprintf(stderr, "Failed to create verification context.\n");
                handle_errors();
            }

            const char msg_verify[] = "This is the string we want to sign.";
            size_t msg_len_verify= strlen(msg);

            const unsigned char *key_verify= public_key;
            size_t key_length_verify = strlen(public_key);

            OSSL_DECODER_CTX* dctx;
            EVP_PKEY* pkey_verify = NULL;

            const unsigned char *sig_verify = signature;
            size_t sig_len_verify = (size_t)64;

            dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey_verify, "PEM", NULL, "ED25519", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
            if (dctx == NULL) {
                fprintf(stderr, "Failed to create decoder context\n");
                handle_errors();
            }

            if (!OSSL_DECODER_from_data(dctx, &key_verify, &key_length_verify)) {
                fprintf(stderr, "Failed to import public key\n");
                handle_errors();
            }

            // Initialize the verification operation
            if (EVP_DigestVerifyInit(mdctx_verify, NULL, NULL, NULL, pkey_verify) <= 0) {
                fprintf(stderr, "Failed to initialize digest verification.\n");
                handle_errors();
            }


            // Perform the verification
            // EVP_DigestVerify returns 1 for a successful verification, 0 for failure,
            // and a negative value for other errors.
            int verification_status = EVP_DigestVerify(mdctx_verify, sig_verify, sig_len_verify, (const unsigned char *)msg_verify, msg_len_verify);

            if (verification_status == 1) {
                // printf("--- VERIFICATION SUCCESS ---\n");
                // printf("The signature is valid.\n");
            } else if (verification_status == 0) {
                // printf("--- VERIFICATION FAILED ---\n");
                // printf("The signature is NOT valid.\n");
            } else {
                // fprintf(stderr, "An error occurred during verification.\n");
                handle_errors();
            }
            EVP_MD_CTX_free(mdctx_verify);
            OSSL_DECODER_CTX_free(dctx);
            break;
    }
    return 0;
}
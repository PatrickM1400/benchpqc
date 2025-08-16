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
                                "MEMwBQYDK2VxAzoAKpxABW+lhNBhu/PJr+REfEeLwhpifeCTiebyN/DYpEHULcno\n"
                                "yUUXh8IPUOjILzfRxaJrhJ25PbGA\n"
                                "-----END PUBLIC KEY-----";

const unsigned char private_key[] = "-----BEGIN PRIVATE KEY-----\n"
                                "MEcCAQAwBQYDK2VxBDsEORMMK1LjumppA+kpjollraHNTUee+dctANctGuF1O0Gz\n"
                                "2EDvSbgcO+nfkK6iVFo6mobYacI5Hyooug==\n"
                                "-----END PRIVATE KEY-----";

 unsigned char signature[114] = {0xf6,0x8b,0x68,0x90,0x0e,0xf2,0x68,0x2d,0xd2,0xec,0x0c,0x7b,0x38,0xce,0xfb,0xe4,0xdb,0xba,0x13,0x3c,0x3d,0x5d,0xc8,0x2d,0xc9,0xd8,0xbd,0xec,0x33,0x19,0x93,0xfc,0xe4,0x6a,0x4c,0xee,0x6f,0x45,0x9b,0x4b,0xaa,0x75,0xd0,0xda,0xb9,0x23,0x70,0xe6,0xe8,0x70,0xd0,0x1d,0xf9,0xeb,0x2d,0x87,0x80,0xb5,0xc9,0xb9,0x37,0x72,0x62,0xc6,0x2e,0xda,0x4d,0xdd,0x35,0x50,0xd5,0xd0,0xce,0x50,0x24,0xa6,0x7e,0x44,0x8f,0xd9,0xd5,0xc9,0x1e,0x10,0x2a,0x5b,0xfb,0xa5,0xff,0x44,0x1f,0x14,0x65,0xd3,0xd0,0xf6,0x99,0xac,0x40,0x47,0x0a,0x26,0x96,0xc7,0xdb,0x93,0x47,0xc2,0x87,0x0f,0xcb,0x45,0x1b,0x00};

 // Function to handle OpenSSL errors
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {

    if (argc != 2){
		printf("Invalid number of command line arguments\n");
		printf("./bench_ed448 <CRYPTO_OPERATION>");
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
            // This section generates a new Ed448 key pair.
            EVP_PKEY *pkey = NULL;
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
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

            // printf("--- Private Key ---\n");
            // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
            // printf("\n--- Public Key ---\n");
            // PEM_write_PUBKEY(stdout, pkey);
            // printf("\n");

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

            dctx_signature = OSSL_DECODER_CTX_new_for_pkey(&pkey_signatuare, "PEM", NULL, "ED448", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
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

            // for(int i = 0; i < sig_len; ++i) printf("0x%02x,", sig[i]);

            // printf("\n%d", sig_len);
            
 
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
            size_t sig_len_verify = (size_t)114;

            dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey_verify, "PEM", NULL, "ED448", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
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
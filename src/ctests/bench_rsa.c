#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/decoder.h>

#define KEYGEN 1
#define SIGNATURE 2
#define VERIFY 3

const unsigned char public_key[] =  "-----BEGIN PUBLIC KEY-----\n"
                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6eRUZ+AdVyxTqK3/zIIv\n"
                                    "zraBH9S0hiNknhanzuj1p070pP+R+s6bm/WMzzksp5KT+byBe//1ZYvZYE+p6zce\n"
                                    "HqNR+6SZgSdSgRoCn7vOwKTAV6gc1eyP09r1JJjYgXWU1MTV9QEca1oxHz5nYawx\n"
                                    "JYOoB92TJzUd/5kz4jxaJaXW9VD7nkbh3N9U3XCjBIm+m1IsNkfsNkG7z/ogSmzV\n"
                                    "DoB0acEr8joh/zr9VnX7M96kX3YuwzW+i21pPXRQIQpaiqwRDrsqtYacMFhd8wJN\n"
                                    "BPzUXNccEi+UjQjJvvRadC8fB4Diklu2DIQdKAq9pmNrmHKXwaUB9CIVIS42UEbq\n"
                                    "mQIDAQAB\n"
                                    "-----END PUBLIC KEY-----\n";

const unsigned char private_key[] = "-----BEGIN PRIVATE KEY-----\n"
                                    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDp5FRn4B1XLFOo\n"
                                    "rf/Mgi/OtoEf1LSGI2SeFqfO6PWnTvSk/5H6zpub9YzPOSynkpP5vIF7//Vli9lg\n"
                                    "T6nrNx4eo1H7pJmBJ1KBGgKfu87ApMBXqBzV7I/T2vUkmNiBdZTUxNX1ARxrWjEf\n"
                                    "PmdhrDElg6gH3ZMnNR3/mTPiPFolpdb1UPueRuHc31TdcKMEib6bUiw2R+w2QbvP\n"
                                    "+iBKbNUOgHRpwSvyOiH/Ov1Wdfsz3qRfdi7DNb6LbWk9dFAhClqKrBEOuyq1hpww\n"
                                    "WF3zAk0E/NRc1xwSL5SNCMm+9Fp0Lx8HgOKSW7YMhB0oCr2mY2uYcpfBpQH0IhUh\n"
                                    "LjZQRuqZAgMBAAECggEAODsYv9B1vVt+0XLjqLsz2zKtYIW20Pj5W7h+p5QCWzL0\n"
                                    "RibbZbz+VER4kelg/viSctwLFVC4Iq24mRsN8urRZvRE5YbxEMfvYfJq5xQz5MS3\n"
                                    "KVvVcujouzpM7XuBsb4fBfg8qCaYOob4gFZ0bFsFhctdPmba1fZDPAwNGTsBQUNj\n"
                                    "/U4kYLei1Lxt04oMYMmWtYhubME/kHasDt4X5W444Jpxy/72tdhzGqQabOsH+XKF\n"
                                    "3UetFvLQ/+gYJ3k18mQwigXVFITv3y4vT9Mq8JNIMsavrZJ1oCFv5EfurxAGmaiT\n"
                                    "LXyYKM0GHyw5HKFL1bNZDB0QAnrG1XgLxjH/lGYecQKBgQD2Y6j5JgrTMC+G3Jb6\n"
                                    "ojNGiRVdNvf5d8Bhyzsg0VXy0VSo7cL1ogufQMfpjqV4iA7qj9tW9ZGg8/YeOSJR\n"
                                    "lVC+MwNO5FRO6AIvPt9BOT+v23O1q/cbsxB1gc6yJdTSqfK1jt+QNrASmRRLFKXy\n"
                                    "HyJnYfVE2nrKz1IRjymFF0dNtwKBgQDzA+BDvUFDkj9UFJwMKhan60G/o+AHQOf2\n"
                                    "0SxVRN36oTQTIUDIuZxlMBEeSuC+Y+QDpOFzJ4Z7ATBSXi5KhuGIWqzeEtecoSjx\n"
                                    "TCkQL797VVuWE01DuatfKYQA/2AKIoHfuLcRJjqBpwBr1LQC+2gIDlsSTyufteQT\n"
                                    "dPBBmA2KLwKBgG8KuzyOSJKlRMYi5GhQcYt4fIhmHZvwvGNWlG9V6MZmUSFRBmxt\n"
                                    "e49qQq6f+zM3HoHYE6I9SkSfrmwwk6bxBFKz6unDPbvSFCn2y+c5RdqbrKpTtipl\n"
                                    "qSVMOztOkXvf2+K3YUo9W10GYH7171QPdBHjtAYz8OM2TGZdfvjcZOZBAoGAc/GR\n"
                                    "ekA9dyO7mz4KBbO/A3a289wX8t4Azj2WTUiCMCXhVo8y/ZGxEIYSZMWM3MmD7Ekq\n"
                                    "V2qwOteiWmoc4+neiNPaTknnHQ+3HQkdPl/Jl+ptu/iRkJJxNQH1vRQamjtEg5z5\n"
                                    "mvEGUP2AsfHVwOZ6B/3xbZbgVV7O5omQZ3tIWnkCgYBj37BCWfu2gSAc6myFtCOb\n"
                                    "Lc4FW0jFRjhArbOC8S0BEir0MI5+w8/QDsyVgET39WtVeuNSS29L/hCUHBuwTj41\n"
                                    "ZTi6+OsfdSL79/iglYk4KOxCC4Mn6Ly+bZMFB+7V3HO1PGSRxYAXd1dM4DpestFd\n"
                                    "J1uiWlCCZI2ThGG/lGoXjg==\n"
                                    "-----END PRIVATE KEY-----\n";

unsigned char signature[256] = {0x91,0xae,0x64,0xff,0x3a,0x60,0xc8,0xf9,0xd5,0xed,0x6a,0x4b,0xcb,0x6f,0x84,0x38,0x13,0xa8,0x73,0x2a,0x2f,0x30,0x64,0xef,0xb9,0x2c,0x0e,0x2e,0x5c,0x12,0x00,0x74,0x53,0x43,0xcb,0x69,0x50,0x79,0x48,0x80,0xe6,0x1b,0x17,0x90,0xae,0xd9,0x1b,0x86,0x22,0x7c,0x9c,0x70,0xd5,0x77,0x16,0x33,0x9b,0xf3,0x0c,0x60,0x34,0x81,0x98,0x73,0x7f,0xac,0x25,0x38,0x03,0xb1,0xa6,0xd7,0xbc,0xf4,0xa1,0xcb,0xdc,0xa2,0x86,0xe4,0x3b,0x53,0x6c,0xdb,0x5d,0x80,0xba,0xf2,0xc3,0xa5,0x89,0x84,0x43,0x16,0xf5,0x39,0x4f,0xdb,0x7d,0xd9,0xdd,0x74,0x36,0x01,0x3e,0x9e,0x55,0x3a,0x6a,0x54,0x67,0x6d,0x13,0xa5,0x58,0x98,0x46,0xdf,0xc3,0xda,0x31,0xb7,0x0b,0xdd,0x35,0x9c,0x54,0x5f,0x6f,0xdf,0xd1,0xe4,0xef,0xa1,0x18,0x92,0x07,0xdb,0x37,0xff,0x7f,0xb3,0xdc,0xb0,0x0c,0xbf,0x69,0xd2,0xcd,0xdd,0x4e,0xa4,0xdd,0x56,0x92,0xf6,0x36,0x76,0xa1,0x23,0xcb,0x03,0xf0,0xa6,0xef,0x28,0x82,0xfd,0x5d,0x64,0xe1,0xa7,0x9c,0x34,0x60,0x58,0x27,0x73,0x34,0x1e,0xae,0x45,0x00,0x79,0x86,0xbd,0x01,0xa3,0xba,0x35,0x45,0xa6,0xc1,0x5a,0x85,0xc6,0x60,0xc4,0x06,0xb1,0xf6,0x31,0xf9,0x88,0x23,0x09,0xde,0x7c,0x78,0xd0,0x43,0xb8,0xac,0x75,0xad,0x22,0x4d,0xde,0x2f,0x4f,0xb0,0x93,0x1e,0xc1,0xef,0x76,0xe7,0xc5,0x7c,0xe6,0xb5,0x8a,0xd1,0x9f,0x61,0x14,0xc4,0xe2,0x42,0xc9,0x08,0xf0,0xdc,0x28,0x35,0xf3,0x80,0x6c,0xbb,0x94,0x59,0xa7,0x9d,0x12,0x8d,0x25};

 // Function to handle OpenSSL errors
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {

    if (argc != 2){
		printf("Invalid number of command line arguments\n");
		printf("./bench_rsa <CRYPTO_OPERATION>");
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
            // This section generates a new RSA key pair.
            EVP_PKEY *pkey = NULL;
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
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

            // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
            // PEM_write_PUBKEY(stdout, pkey);

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

            dctx_signature = OSSL_DECODER_CTX_new_for_pkey(&pkey_signatuare, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
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
            size_t sig_len_verify = (size_t)256;

            dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey_verify, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
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
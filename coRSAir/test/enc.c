#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

    int ret = 0;
    BIO *bp_public = NULL;
    RSA* pub_key = NULL;
    const char cert_publickey[] = "./publickey.pem";

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    bp_public = BIO_new(BIO_s_file());
    ret = BIO_read_filename(bp_public, cert_publickey);
    //printf("RET: %d\n", ret);
    if(ret == 1) printf("Clave publica leida\n");
    PEM_read_bio_RSAPublicKey(bp_public, &pub_key, NULL, NULL);
    if(pub_key != NULL) printf("Clave publica cargada\n");












  int bits = 512;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (ctx == NULL) {
    printf("Could not create a context for RSA");
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    printf("Could not initialize the RSA context");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
  }

    EVP_PKEY *pkey  = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, pub_key);


  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    printf("EVP_PKEY_keygen failed");
  }

  EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
    printf("EVP_PKEY_encrypt_init failed");
  }

  unsigned char* in = (unsigned char*) "hola mundo";
  size_t outlen;
  unsigned char* out;

  printf("Going to encrypt: %s, len: %ld\n", in, strlen((char*)in));

  if (EVP_PKEY_encrypt(enc_ctx, NULL, &outlen, in, strlen ((char*)in)) <= 0) {
    printf("EVP_PKEY_encrypt failed");
  }
  printf("Determined ciphertext to be of length: %ld:\n", outlen);

  out = OPENSSL_malloc(outlen);

  if (EVP_PKEY_encrypt(enc_ctx, out, &outlen, in, strlen ((char*)in)) <= 0) {
    printf("EVP_PKEY_encrypt failed");
  }

  printf("Encrypted ciphertext (len:%ld) is:\n", outlen);
  BIO_dump_fp(stdout, (const char*) out, outlen);

  FILE* pubf = fopen("top_secret.txt","w+");
  BIO_dump_fp(pubf, (const char*) out, outlen);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  RSA_free(pub_key);
  BIO_free_all(bp_public);


















 /* ---------------------------------------------------------------------------------------------------- */


 /* ---------------------------------------------------------------------------------------------------- */



















  exit(EXIT_SUCCESS);
}
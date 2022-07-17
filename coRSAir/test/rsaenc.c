#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>

int main() {

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  int ret = 0;
  BIO *bp_public = NULL;
  RSA* pub_key = NULL;
  const char cert_publickey[] = "./publickey.pem";
  bp_public = BIO_new(BIO_s_file());
  ret = BIO_read_filename(bp_public, cert_publickey);
  if(ret == 1) printf("Clave publica leida\n");
  PEM_read_bio_RSAPublicKey(bp_public, &pub_key, NULL, NULL);
  if(pub_key != NULL) printf("Clave publica cargada\n");
  



  EVP_PKEY_CTX *ctx;
  //ENGINE *eng;
  unsigned char *out;
  size_t outlen;
  size_t inlen;
  unsigned char in[100] = "hola mundo";
  inlen = strlen((char*)in);
  printf("Size: %ld\n", inlen);
  EVP_PKEY *key  = EVP_PKEY_new();
  printf("1\n");
  EVP_PKEY_set1_RSA(key, pub_key);
  printf("2\n");

  /*
  * NB: assumes eng, key, in, inlen are already set up,
  * and that key is an RSA public key
  */
  ctx = EVP_PKEY_CTX_new(key, NULL);
  printf("3\n");
  if (!ctx) {
      /* Error occurred */
      printf("4\n");
  }
  printf("5\n");
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
      /* Error */
      printf("6\n");
  }
  //if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
      /* Error */
  //}

  /* int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen); */

  /* Determine buffer length */
  printf("7\n");
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0) {
      //error
      printf("8\n");
  }

  out = OPENSSL_malloc(outlen);
  printf("9\n");

  if (!out) {
      //malloc failure


      if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0) {

          //Error
      }
  }

  /* Encrypted data is outlen bytes written to buffer out */
  //printf("1: %ld\n", outlen);
  //printf("2: %p\n", out);
  printf("Encrypted ciphertext (len:%ld) is:\n", outlen);
  BIO_dump_fp(stdout, (const char*) out, outlen);
  FILE* pubf = fopen("top_secret.txt","w+");
  BIO_dump_fp(pubf, (const char*) out, outlen);



  RSA_free(pub_key);
  BIO_free_all(bp_public);
}




/* 
 int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
 int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
 */
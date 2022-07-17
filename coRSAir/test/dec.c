#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int arc, char *argv[]) {

    int ret = 0;
    BIO *bp_private = NULL;
    RSA* pri_key = NULL;
    const char cert_privatekey[] = "./privatekey.pem";

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    bp_private = BIO_new(BIO_s_file());
    ret = BIO_read_filename(bp_private, cert_privatekey);
    //printf("RET: %d\n", ret);
    if(ret == 1) printf("Clave publica leida\n");
    PEM_read_bio_RSAPublicKey(bp_private, &pri_key, NULL, NULL);
    if(pri_key != NULL) printf("Clave publica cargada\n");





    EVP_PKEY *prkey  = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(prkey, pri_key);
    


  EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(prkey, NULL);
  if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
    printf("EVP_PKEY_encrypt_init failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  //const EVP_MD* digest = EVP_get_digestbyname("sha256");

  /*if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_oaep_md failed");
  }*/

 /* if (EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
  }*/

  unsigned char* dout;
  size_t doutlen;
  if (EVP_PKEY_decrypt(dec_ctx, NULL, &doutlen, out, outlen) <= 0) {
    printf("EVP_PKEY_decrypt get length failed");
  }

  printf("Determimed plaintext to be of length: %ld:\n", doutlen);
  dout = OPENSSL_malloc(doutlen);
  if (!dout) {
    printf("OPENSSL_malloc failed");
  }

  if (EVP_PKEY_decrypt(dec_ctx, dout, &doutlen, out, outlen) <= 0) {
   printf("EVP_PKEY_decrypt failed");
  }

  printf("Decrypted Plaintext is:\n");
  BIO_dump_fp(stdout, (const char*) dout, doutlen);




  EVP_PKEY_CTX_free(dec_ctx);
  EVP_PKEY_free(prkey);
  RSA_free(pri_key);
  BIO_free_all(bp_private);



  exit(EXIT_SUCCESS);
}
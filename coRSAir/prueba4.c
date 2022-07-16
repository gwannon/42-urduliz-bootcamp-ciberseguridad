#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>


int main(){
  int ret = 0;
  unsigned char plainText[1000] = "1234567";
  unsigned char encrypted[1000] = {0};
  int plainText_len;
  BIO *bp_public = NULL;
  RSA* pub_key = NULL;
  const char cert_publickey[] = "./p2_publickey.pem";
  //const char cert_privatekey[] = "./p2_privatekey.pem";

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();

  bp_public = BIO_new(BIO_s_file());
  ret = BIO_read_filename(bp_public, cert_publickey);
  //printf("RET: %d\n", ret);
  if(ret == 1) printf("Clave publica leida\n");
  PEM_read_bio_RSAPublicKey(bp_public, &pub_key, NULL, NULL);
  if(pub_key != NULL) printf("Clave publica cargada\n");


  
  /* --------------------------------------- */
  const BIGNUM *nn;
  const BIGNUM *ee;
  //const BIGNUM *dd;
  RSA_get0_key(pub_key, &nn, &ee, NULL);
  printf("n: %s\n", BN_bn2dec(nn));
  printf("n (hex): %s\n", BN_bn2hex(nn));
  printf("e: %s\n", BN_bn2dec(ee));



  plainText_len = strlen((char*)plainText);
  printf("%d\n", plainText_len);
  int result = RSA_public_encrypt(plainText_len, plainText, encrypted, pub_key, RSA_PKCS1_PADDING);
  printf("%d\n", result);
  printf("%s\n", encrypted);
}
#include <math.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int main() {
  //int ret = 0;
  EVP_PKEY *pub_key;
  const char cert_publickey[] = "./p2_publickey.pem";
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  FILE* pubf = fopen(cert_publickey,"rb");
  pub_key = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);

  //rsa_encrypt
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  unsigned char key[32];
  unsigned char iv[16];
  RAND_bytes(key,32);
  RAND_bytes(iv,16);
  ctx = EVP_PKEY_CTX_new(pub_key, NULL);
  EVP_PKEY_encrypt_init(ctx);
  //EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_encrypt(ctx, NULL, &outlen, key, 32);

  //encrypt
  /*unsigned char *plaintext = (unsigned char *)"This is a test string to encrypt.";
  int plaintext_len = strlen ((char *)plaintext);
  unsigned char ciphertext[1024];
  EVP_CIPHER_CTX *ctx2;
  int len;
  int ciphertext_len;
  ctx2 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx2, ciphertext, &len, plaintext, plaintext_len);
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx2, ciphertext + len, &len);
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx2);

  //File
  FILE *fp = fopen("top-secret.txt", "w+");
  if (fp != NULL)
  {
      fputs( (const char *)ciphertext, fp );
      fclose(fp);
  }*/
 
 //-----------------------------------------------------------------------------

 //const char cert_privatekey[] = "./p2_privatekey.pem";

  return EXIT_SUCCESS;
}

/* gcc -I/usr/include/openssl/ -Wall prueba3.c -o prueba3  -lcrypto -ldl */
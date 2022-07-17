#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include <stdio.h>
int main() {

 BIO* bio = BIO_new_file("top_secret.txt", "r");
  char* in = (char*) malloc(sizeof(char) * 1679);
  if (BIO_read(bio, in, 1679)) {
    printf("data: %s\n", in);
  }

  int ret;
  BIO *bp_private = NULL;
  RSA* pri_key = NULL;
  const char cert_privatekey[] = "./p2_privatekey.pem";

  bp_private = BIO_new(BIO_s_file());
  ret = BIO_read_filename(bp_private, cert_privatekey);
  //printf("RET: %d\n", ret);
  if(ret == 1) printf("Clave privada leida\n");
  PEM_read_bio_RSAPrivateKey(bp_private, &pri_key, NULL, NULL);
  if(pri_key != NULL) printf("Clave privada cargada\n");
  //BIO_dump_fp(stdout, (const char*) pri_key, 100);


  EVP_PKEY_CTX *ctx;
  size_t inlen;


  EVP_PKEY *key  = EVP_PKEY_new();

  EVP_PKEY_set1_RSA(key, pri_key);
  ctx = EVP_PKEY_CTX_new(key,NULL);

  EVP_PKEY_decrypt_init(ctx);





inlen = strlen((char*)in);

  unsigned char* out;
  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (unsigned char *)&in, inlen) <= 0) {
    //error
  }

  printf("Determimed plaintext to be of length: %ld:\n", outlen);
  out = OPENSSL_malloc(outlen);
  if (!out) {
   //error
  }

  if (EVP_PKEY_decrypt(ctx, out, &outlen, (unsigned char *)&in, inlen) <= 0) {
    //error
  }

  printf("Decrypted Plaintext is:\n");
  BIO_dump_fp(stdout, (const char*) out, outlen);






/*int rsa_decrypt(unsigned char* in, size_t inlen, ------EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}*/

//int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, ----privkey, decrypted_key); 

/*int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}*/


/*FILE* privf = fopen(privfilename,"rb");
  privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
  unsigned char decrypted_key[32];
  int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, privkey, decrypted_key); 
  
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv,
			      decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);*/



}

/* gcc -I/usr/include/openssl/ -Wall prueba5-2.c -o prueba5-2  -lcrypto -ldl */
#include <openssl/evp.h>
 #include <openssl/rsa.h>
 #include <openssl/engine.h>
#include <string.h>
#include <stdio.h>
int main() {


    int ret = 0;
    BIO *bp_public = NULL;
    RSA* pub_key = NULL;
    const char cert_publickey[] = "./p2_publickey.pem";

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();

    bp_public = BIO_new(BIO_s_file());
    ret = BIO_read_filename(bp_public, cert_publickey);
    //printf("RET: %d\n", ret);
    if(ret == 1) printf("Clave publica leida\n");
	PEM_read_bio_RSAPublicKey(bp_public, &pub_key, NULL, NULL);
    if(pub_key != NULL) printf("Clave publica cargada\n");


    EVP_PKEY_CTX *ctx;
    //ENGINE *eng;
    unsigned char *out;
    size_t outlen;
    size_t inlen;
    unsigned char in[1000] = "1234567890";
    inlen = strlen((char*)in);
    printf("%ld\n", inlen);
    EVP_PKEY *key  = EVP_PKEY_new();

    EVP_PKEY_set1_RSA(key, pub_key);


    /*
    * NB: assumes eng, key, in, inlen are already set up,
    * and that key is an RSA public key
    */
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) {
        /* Error occurred */
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        /* Error */
    }
    //if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        /* Error */
    //}

    /* int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
 int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen); */

    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0) {
        //error
    }

    out = OPENSSL_malloc(outlen);

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

    /* https://github.com/danbev/learning-openssl/blob/master/rsa_data_too_large.c */
    /* https://headerfiles.com/2019/03/12/breve-introduccion-al-uso-de-rsa-con-openssl/ */
    /* ------------------------------------------------------------ */


echo '1234567890' > plain.txt
openssl rsautl -encrypt -inkey p2_publickey.pem -pubin -in plain.txt -out plain.txt.enc
openssl rsautl -encrypt -inkey pub.pem -pubin -in plain.txt -out plain.txt.enc

openssl rsautl -decrypt -inkey key.pem -pubin -out plain2.txt -in plain.txt.enc





}
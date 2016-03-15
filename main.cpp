#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv))
        handleErrors();
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv))
        handleErrors();
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}


void test_encrypt_decrypt_result(unsigned char *plaintext, unsigned char *key, unsigned char *iv)
{
    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[1024];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[1024];

    int decryptedtext_len, ciphertext_len;

    clock_t start = clock();

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, static_cast<int>(strlen((char *)plaintext)), key, iv, ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext(length: %d) is:\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    printf("\n\n");

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text(length: %d) is:\n", decryptedtext_len);
    printf("%s\n\n", decryptedtext);

    std::cout << "Elapsed time: " << static_cast<double>(clock() - start) /CLOCKS_PER_SEC << "s.\n\n" << std::endl;
}


void test_encrypt_decrypt_performance(unsigned char *plaintext, unsigned char *key, unsigned char *iv)
{
    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[1024];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[1024];

    int ciphertext_len;

    clock_t start = clock();
    double elapsedTime = 0.0;
    int runTimes = 0;
    while (runTimes < 800000) {
        ++runTimes;
        /* Encrypt the plaintext */
        ciphertext_len = encrypt(plaintext, static_cast<int>(strlen((char *)plaintext)), key, iv, ciphertext);

        /* Decrypt the ciphertext */
        decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    }
    elapsedTime = static_cast<double>(clock() - start) /CLOCKS_PER_SEC;
    std::cout << "Encrypt and decrypt total run times: " << runTimes << " elapsed Time: " << elapsedTime << "s.\n\n" << std::endl;
}


void test_encrypt_preformance(unsigned char *plaintext, unsigned char *key, unsigned char *iv)
{
    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[1024];

    clock_t start = clock();
    double elapsedTime = 0.0;
    int runTimes = 0;
    while (runTimes < 1600000) {
        ++runTimes;

        /* Encrypt the plaintext */
        encrypt(plaintext, static_cast<int>(strlen((char *)plaintext)), key, iv, ciphertext);
    }
    elapsedTime = static_cast<double>(clock() - start) /CLOCKS_PER_SEC;
    std::cout << "Encrypt total run times: " << runTimes << " elapsed Time: " << elapsedTime << "s.\n\n" << std::endl;
}


void test_decrypt_performance(unsigned char *plaintext, unsigned char *key, unsigned char *iv)
{
    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[1024];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[1024];

    int ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, static_cast<int>(strlen((char *)plaintext)), key, iv, ciphertext);

    clock_t start = clock();
    double elapsedTime = 0.0;
    int runTimes = 0;
    while (runTimes < 1600000) {
        ++runTimes;

        /* Decrypt the ciphertext */
        decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    }

    elapsedTime = static_cast<double>(clock() - start) /CLOCKS_PER_SEC;
    std::cout << "Decrypt total run times: " << runTimes << " elapsed Time: " << elapsedTime << "s.\n\n" << std::endl;
}


void GenerateKey()
{
    // Key and IV values.
    const char *pcCode = "543210";

    unsigned char acKey[EVP_MAX_KEY_LENGTH + 1];
    unsigned char acIV[EVP_MAX_IV_LENGTH + 1];

    // Load all the encryption ciphers and lookup the one we want to use.
    OpenSSL_add_all_algorithms();
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-128-xts");
    const EVP_MD *digest = EVP_get_digestbyname("sha1");

    // Generate HashKey for the password.
    int nrounds = 2;
    int nCnt = EVP_BytesToKey(cipher, digest, NULL, (const unsigned char *) pcCode, strlen(pcCode), nrounds, acKey, acIV);

    std::cout << "nCnt: " << nCnt << " key length: " << EVP_MAX_KEY_LENGTH << " iv length: " << EVP_MAX_IV_LENGTH << std::endl;
    BIO_dump_fp(stdout, (const char*)acKey, nCnt);
    printf("\n\n");
    BIO_dump_fp(stdout, (const char*)acIV, EVP_MAX_IV_LENGTH);
}


int main() {
    /* Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */
    
    /* A 128 bit key */
    unsigned char *key = (unsigned char *)"0123456789012345601234567890123456";
    
    /* A 128 bit IV (Initialization Vector) */
    unsigned char *iv =  (unsigned char *)"01234567890123456";
    
    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)
        "The Advanced Encryption Standard (AES), also known as Rijndael(its original name), is a specificatio"
        "n for the encryption of electronic data established by the U.S. National Institute of Standards and "
        "Technology (NIST) in 2001. AES is based on the Rijndael cipher developed by two Belgian cryptographe"
        "rs, Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES selection proces"
        "s. Rijndael is a family of ciphers with different key and block sizes. For AES, NIST selected three "
        "members of the Rijndael family, each with a block size of 128 bits, but three different key lengths:"
        " 128, 192 and 256 bits. AES has been adopted by the U.S. government and is now used worldwide. It su"
        "persedes the Data Encryption Standard (DES), which was published in 1977. The algorithm described by"
        " AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting t"
        "he data. In the United States, AES was announced by the NIST as U.S. FIPS PUB 197 on November 26, 20"
        "01.";

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Test cases */

//    test_encrypt_decrypt_result(plaintext, key, iv);

    test_encrypt_decrypt_performance(plaintext, key, iv);

    test_encrypt_preformance(plaintext, key, iv);

    test_decrypt_performance(plaintext, key, iv);

//    GenerateKey();

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}



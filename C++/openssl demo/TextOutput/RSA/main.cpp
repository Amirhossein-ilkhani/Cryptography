#include <iostream>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate an RSA key pair
    RSA* rsa_keypair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr); //Generates Key pair
    if (!rsa_keypair) {
        std::cerr << "Failed to generate RSA key pair." << std::endl;
        return 1;
    }

    // Public key and private key
    BIO* bio_pub = BIO_new(BIO_s_mem());
    BIO* bio_priv = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPublicKey(bio_pub, rsa_keypair); //Assigns public key to bio
    PEM_write_bio_RSAPrivateKey(bio_priv, rsa_keypair, nullptr, nullptr, 0, nullptr, nullptr); //Assigns private key to bio

    char* pub_key_data;
    char* priv_key_data;
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key_data);
    long priv_key_len = BIO_get_mem_data(bio_priv, &priv_key_data);

    // Print public and private keys
    std::cout << "Public Key:" << std::endl << pub_key_data << std::endl;
    std::cout << "Private Key:" << std::endl << priv_key_data << std::endl;

    // Encrypt and decrypt a message
    const char* message = "Hello, RSA!";
    unsigned char encrypted[256]; // Sufficient buffer for a 2048-bit RSA key
    unsigned char decrypted[256];

    int encrypted_len = RSA_public_encrypt(strlen(message), (const unsigned char*)message, encrypted, rsa_keypair, RSA_PKCS1_PADDING);
    int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa_keypair, RSA_PKCS1_PADDING);

    if (encrypted_len == -1 || decrypted_len == -1) {
        std::cerr << "Encryption or decryption failed." << std::endl;
        return 1;
    }

    decrypted[decrypted_len] = '\0';
    std::cout << "Decrypted Message: " << decrypted << std::endl;

    RSA_free(rsa_keypair);
    BIO_free_all(bio_pub);
    BIO_free_all(bio_priv);

    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}

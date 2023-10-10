#include <iostream>
#include <string>
#include <bits/stdc++.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Function to perform AES encryption in CBC mode
std::string encrypt_aes_cbc(const std::string &plaintext, const std::string &key, const std::string &iv)
{
    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) < 0)
    {
        std::cerr << "Error: Failed to set AES encryption key." << std::endl;
        return "";
    }

    // Check if the IV length is correct for AES
    if (iv.length() != 16)
    {
        std::cerr << "Error: IV length must be 16 bytes for AES" << std::endl;
        return "";
    }

    // Encrypt the plaintext using AES in CBC mode
    std::string ciphertext = plaintext;
    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                    reinterpret_cast<unsigned char *>(const_cast<char *>(ciphertext.c_str())),
                    plaintext.length(),
                    &aesKey,
                    reinterpret_cast<unsigned char *>(const_cast<char *>(const_cast<char *>(iv.c_str()))),
                    AES_ENCRYPT);

    return ciphertext;
}

// Function to perform AES decryption in CBC mode
std::string decrypt_aes_cbc(const std::string &ciphertext, const std::string &key, const std::string &iv)
{
    AES_KEY aesKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) < 0)
    {
        std::cerr << "Error: Failed to set AES decryption key." << std::endl;
        return "";
    }

    // Check if the IV length is correct for AES
    if (iv.length() != 16)
    {
        std::cerr << "Error: IV length must be 16 bytes for AES" << std::endl;
        return "";
    }

    // Decrypt the ciphertext using AES in CBC mode
    std::string plaintext = ciphertext;
    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(ciphertext.c_str()),
                    reinterpret_cast<unsigned char *>(const_cast<char *>(plaintext.c_str())),
                    ciphertext.length(),
                    &aesKey,
                    reinterpret_cast<unsigned char *>(const_cast<char *>(const_cast<char *>(iv.c_str()))),
                    AES_DECRYPT);

    return plaintext;
}

// Function to perform AES encryption in ECB mode
std::string encrypt_aes_ecb(const std::string &plaintext, const std::string &key)
{
    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) < 0)
    {
        std::cerr << "Error: Failed to set AES encryption key." << std::endl;
        return "";
    }

    // Encrypt the plaintext using AES in ECB mode
    std::string ciphertext = plaintext;
    AES_ecb_encrypt(reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                    reinterpret_cast<unsigned char *>(const_cast<char *>(ciphertext.c_str())),
                    &aesKey,
                    AES_ENCRYPT);

    return ciphertext;
}

// Function to perform AES decryption in ECB mode
std::string decrypt_aes_ecb(const std::string &ciphertext, const std::string &key)
{
    AES_KEY aesKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey) < 0)
    {
        std::cerr << "Error: Failed to set AES decryption key." << std::endl;
        return "";
    }

    // Decrypt the ciphertext using AES in ECB mode
    std::string plaintext = ciphertext;
    AES_ecb_encrypt(reinterpret_cast<const unsigned char *>(ciphertext.c_str()),
                    reinterpret_cast<unsigned char *>(const_cast<char *>(plaintext.c_str())),
                    &aesKey,
                    AES_DECRYPT);

    return plaintext;
}

int main()
{
    std::clock_t cbc_start, cbc_end, ecb_start, ecb_end;
    std::string key = "0123456789abcdef0123456789abcdef"; // 32-byte key for AES-128
    std::string iv = "0123456789abcdef";                  // 16-byte IV for CBC mode
    std::string plaintext = "Hello, OpenSSL AES in CBC and ECB mode!";
    std::string encrypted_cbc, decrypted_cbc, encrypted_ecb, decrypted_ecb;
    cbc_start = std::clock();
    // Encrypt and Decrypt using AES in CBC mode
    encrypted_cbc = encrypt_aes_cbc(plaintext, key, iv);
    decrypted_cbc = decrypt_aes_cbc(encrypted_cbc, key, iv);
    cbc_end = std::clock();

    std::cout << "AES CBC Encrypted: " << encrypted_cbc << std::endl;
    std::cout << "AES CBC Decrypted: " << decrypted_cbc << std::endl;

    ecb_start = std::clock();
    // Encrypt and Decrypt using AES in ECB mode
    encrypted_ecb = encrypt_aes_ecb(plaintext, key);
    decrypted_ecb = decrypt_aes_ecb(encrypted_ecb, key);
    ecb_end = std::clock();
    std::cout << "AES ECB Encrypted: " << encrypted_ecb << std::endl;
    std::cout << "AES ECB Decrypted: " << decrypted_ecb << std::endl;

    double cbc_execution_time = double(cbc_end - cbc_start) / double(CLOCKS_PER_SEC);
    double ecb_execution_time = double(ecb_end - ecb_start) / double(CLOCKS_PER_SEC);
    std::cout << "Time taken by this encryption in CBC is " << cbc_execution_time << std::fixed << std::setprecision(10)
              << " seconds" << std::endl;
    std::cout << "Time taken by this encryption in ECB is " << ecb_execution_time << std::fixed << std::setprecision(10)
              << " seconds" << std::endl;

    return 0;
}

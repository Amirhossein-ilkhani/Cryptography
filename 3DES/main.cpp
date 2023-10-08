#include <bits/stdc++.h>
#include <iostream>
#include <string>
#include <cstring>
#include <openssl/des.h>
#include <openssl/rand.h>

// Function to perform 3DES encryption
std::string encrypt_3des(const std::string &plaintext, const std::string &key, const std::string &iv)
{
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;

    // Check if the key length is correct for 3DES
    if (key.length() != 24)
    {
        std::cerr << "Error: Key length must be 24 bytes for 3DES" << std::endl;
        return "";
    }

    // Split the 24-byte key into three 8-byte keys
    memcpy(des_key1, key.c_str(), 8);
    memcpy(des_key2, key.c_str() + 8, 8);
    memcpy(des_key3, key.c_str() + 16, 8);

    DES_set_odd_parity(&des_key1);
    DES_set_odd_parity(&des_key2);
    DES_set_odd_parity(&des_key3);

    DES_set_key_checked(&des_key1, &ks1);
    DES_set_key_checked(&des_key2, &ks2);
    DES_set_key_checked(&des_key3, &ks3);

    DES_cblock des_iv;

    // Encrypt the plaintext using 3DES
    std::string ciphertext = plaintext;
    memcpy(des_iv, iv.c_str(), 8);

    DES_ede3_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                         reinterpret_cast<unsigned char *>(const_cast<char *>(ciphertext.c_str())),
                         plaintext.length(),
                         &ks1, &ks2, &ks3,
                         &des_iv,
                         DES_ENCRYPT);

    return ciphertext;
}
std::string decrypt_3des(const std::string &ciphertext, const std::string &key, const std::string &iv)
{
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock des_iv;

    // Check if the key length is correct for 3DES
    if (key.length() != 24)
    {
        std::cerr << "Error: Key length must be 24 bytes for 3DES" << std::endl;
        return "";
    }

    // Split the 24-byte key into three 8-byte keys
    memcpy(des_key1, key.c_str(), 8);
    memcpy(des_key2, key.c_str() + 8, 8);
    memcpy(des_key3, key.c_str() + 16, 8);

    DES_set_odd_parity(&des_key1);
    DES_set_odd_parity(&des_key2);
    DES_set_odd_parity(&des_key3);

    DES_set_key_checked(&des_key1, &ks1);
    DES_set_key_checked(&des_key2, &ks2);
    DES_set_key_checked(&des_key3, &ks3);

    // Set the initialization vector
    memcpy(des_iv, iv.c_str(), 8);

    // Decrypt the ciphertext using 3DES in CBC mode
    std::string plaintext = ciphertext;
    DES_ede3_cbc_encrypt(reinterpret_cast<const unsigned char *>(ciphertext.c_str()),
                         reinterpret_cast<unsigned char *>(const_cast<char *>(plaintext.c_str())),
                         ciphertext.length(),
                         &ks1, &ks2, &ks3,
                         &des_iv,
                         DES_DECRYPT);

    return plaintext;
}

// Function to perform 3DES encryption in ECB mode
std::string encrypt_3des_ecb(const std::string &plaintext, const std::string &key)
{
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;

    // Check if the key length is correct for 3DES
    if (key.length() != 24)
    {
        std::cerr << "Error: Key length must be 24 bytes for 3DES" << std::endl;
        return "";
    }

    // Split the 24-byte key into three 8-byte keys
    memcpy(des_key1, key.c_str(), 8);
    memcpy(des_key2, key.c_str() + 8, 8);
    memcpy(des_key3, key.c_str() + 16, 8);

    DES_set_odd_parity(&des_key1);
    DES_set_odd_parity(&des_key2);
    DES_set_odd_parity(&des_key3);

    DES_set_key_checked(&des_key1, &ks1);
    DES_set_key_checked(&des_key2, &ks2);
    DES_set_key_checked(&des_key3, &ks3);

    // Encrypt the plaintext using 3DES in ECB mode
    std::string ciphertext;
    ciphertext.resize(plaintext.size());

    for (size_t i = 0; i < plaintext.size(); i += 8)
    {
        DES_cblock block;
        memcpy(block, plaintext.c_str() + i, 8);

        DES_ecb3_encrypt(&block,
                         reinterpret_cast<DES_cblock *>(const_cast<char *>(ciphertext.c_str() + i)),
                         &ks1, &ks2, &ks3,
                         DES_ENCRYPT);
    }

    return ciphertext;
}

// Function to perform 3DES decryption in ECB mode
std::string decrypt_3des_ecb(const std::string &ciphertext, const std::string &key)
{
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;

    // Check if the key length is correct for 3DES
    if (key.length() != 24)
    {
        std::cerr << "Error: Key length must be 24 bytes for 3DES" << std::endl;
        return "";
    }

    // Split the 24-byte key into three 8-byte keys
    memcpy(des_key1, key.c_str(), 8);
    memcpy(des_key2, key.c_str() + 8, 8);
    memcpy(des_key3, key.c_str() + 16, 8);

    DES_set_odd_parity(&des_key1);
    DES_set_odd_parity(&des_key2);
    DES_set_odd_parity(&des_key3);

    DES_set_key_checked(&des_key1, &ks1);
    DES_set_key_checked(&des_key2, &ks2);
    DES_set_key_checked(&des_key3, &ks3);

    // Decrypt the ciphertext using 3DES in ECB mode
    std::string plaintext;
    plaintext.resize(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += 8)
    {
        DES_cblock block;
        memcpy(block, ciphertext.c_str() + i, 8);

        DES_ecb3_encrypt(&block,
                         reinterpret_cast<DES_cblock *>(const_cast<char *>(plaintext.c_str() + i)),
                         &ks1, &ks2, &ks3,
                         DES_DECRYPT);
    }

    return plaintext;
}

int main()
{
    std::clock_t cbc_start, cbc_end, ecb_start, ecb_end;

    std::string key = "123456789012345678901234"; // 24-byte key
    std::string iv = "abcdefgh";                  // 8-byte IV
    std::string plaintext = "Hello, OpenSSL 3DES!";
    std::string encrypted, decrypted;
    // Encrypt the plaintext
    cbc_start = std::clock();
    encrypted = encrypt_3des(plaintext, key, iv);
    // Decrypt the ciphertext
    decrypted = decrypt_3des(encrypted, key, iv);
    cbc_end = std::clock();

    std::cout << "Encrypted in CBC: " << encrypted << std::endl;
    std::cout << "Decrypted in CBC: " << decrypted << std::endl;

    ecb_start = std::clock();
    encrypted = encrypt_3des_ecb(plaintext, key);
    // Decrypt the ciphertext
    decrypted = decrypt_3des_ecb(encrypted, key);
    ecb_end = std::clock();

    std::cout << "Encrypted in ECB: " << encrypted << std::endl;
    std::cout << "Decrypted in ECB: " << decrypted << std::endl;

    double cbc_execution_time = double(cbc_end - cbc_start) / double(CLOCKS_PER_SEC);
    double ecb_execution_time = double(ecb_end - ecb_start) / double(CLOCKS_PER_SEC);
    std::cout << "Time taken by this encryption in CBC is " << cbc_execution_time << std::fixed << std::setprecision(10)
              << " seconds" << std::endl;
    std::cout << "Time taken by this encryption in ECB is " << ecb_execution_time << std::fixed << std::setprecision(10)
              << " seconds" << std::endl;
    return 0;
}
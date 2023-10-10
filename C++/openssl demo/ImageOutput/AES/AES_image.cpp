#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>

// AES encryption in CBC mode
void aes_encrypt_cbc(const char* inputFileName, const char* outputFileName, const unsigned char* key, const unsigned char* iv, int keySize) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary);

    AES_KEY aesKey;
    AES_set_encrypt_key(key, keySize, &aesKey);

    unsigned char inputBlock[AES_BLOCK_SIZE];
    unsigned char outputBlock[AES_BLOCK_SIZE];
    unsigned char previousCipherBlock[AES_BLOCK_SIZE];
    memset(previousCipherBlock, 0, AES_BLOCK_SIZE);

    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char*>(inputBlock), AES_BLOCK_SIZE);

        // XOR the input block with the previous ciphertext block
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            inputBlock[i] ^= previousCipherBlock[i];
        }

        // Encrypt the block
        AES_encrypt(inputBlock, outputBlock, &aesKey);

        // Write the ciphertext to the output file
        outputFile.write(reinterpret_cast<char*>(outputBlock), AES_BLOCK_SIZE);

        // Update the previous ciphertext block
        memcpy(previousCipherBlock, outputBlock, AES_BLOCK_SIZE);
    }

    inputFile.close();
    outputFile.close();
}

// AES decryption in CBC mode
void aes_decrypt_cbc(const char* inputFileName, const char* outputFileName, const unsigned char* key, const unsigned char* iv, int keySize) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary);

    AES_KEY aesKey;
    AES_set_decrypt_key(key, keySize, &aesKey);

    unsigned char inputBlock[AES_BLOCK_SIZE];
    unsigned char outputBlock[AES_BLOCK_SIZE];
    unsigned char previousCipherBlock[AES_BLOCK_SIZE];
    memset(previousCipherBlock, 0, AES_BLOCK_SIZE);

    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char*>(inputBlock), AES_BLOCK_SIZE);

        // Decrypt the block
        AES_decrypt(inputBlock, outputBlock, &aesKey);

        // XOR the decrypted block with the previous ciphertext block
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            outputBlock[i] ^= previousCipherBlock[i];
        }

        // Write the plaintext to the output file
        outputFile.write(reinterpret_cast<char*>(outputBlock), AES_BLOCK_SIZE);

        // Update the previous ciphertext block
        memcpy(previousCipherBlock, inputBlock, AES_BLOCK_SIZE);
    }

    inputFile.close();
    outputFile.close();
}

int main() {
    const char* inputFileName = "input_image.jpg";
    const char* encryptedFileName = "encrypted_image.jpg";
    const char* decryptedFileName = "decrypted_image.jpg";

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int keySize = 128; // You can change the key size here

    // Generate a random key
    unsigned char key[keySize / 8];
    RAND_bytes(key, keySize / 8);

    // Encrypt the image
    aes_encrypt_cbc(inputFileName, encryptedFileName, key, iv, keySize);
    std::cout << "Encryption completed." << std::endl;

    // Decrypt the image
    aes_decrypt_cbc(encryptedFileName, decryptedFileName, key, iv, keySize);
    std::cout << "Decryption completed." << std::endl;

    return 0;
}

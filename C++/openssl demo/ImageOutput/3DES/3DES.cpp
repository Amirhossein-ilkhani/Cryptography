#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/des.h>
#include <openssl/rand.h>

// Function to perform 3DES encryption in CBC mode
void des3_encrypt_cbc(const char* inputFileName, const char* outputFileName, const unsigned char* key, const unsigned char* iv) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary);

    DES_cblock desKey1, desKey2, desKey3;nnnn
    DES_key_schedule ks1, ks2, ks3;

    // Split the 24-byte key into three 8-byte DES keys
    memcpy(desKey1, key, 8);
    memcpy(desKey2, key + 8, 8);
    memcpy(desKey3, key + 16, 8);

    DES_set_key(&desKey1, &ks1);
    DES_set_key(&desKey2, &ks2);
    DES_set_key(&desKey3, &ks3);

    DES_cblock previousCipherBlock;
    memcpy(previousCipherBlock, iv, 8);

    unsigned char inputBlock[8];
    unsigned char outputBlock[8];

    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char*>(inputBlock), 8);

        // XOR the input block with the previous ciphertext block
        for (int i = 0; i < 8; i++) {
            inputBlock[i] ^= previousCipherBlock[i];
        }

        // Encrypt the block
        DES_ecb3_encrypt((DES_cblock*)inputBlock, (DES_cblock*)outputBlock, &ks1, &ks2, &ks3, DES_ENCRYPT);

        // Write the ciphertext to the output file
        outputFile.write(reinterpret_cast<char*>(outputBlock), 8);

        // Update the previous ciphertext block
        memcpy(previousCipherBlock, outputBlock, 8);
    }

    inputFile.close();
    outputFile.close();
}

// Function to perform 3DES decryption in CBC mode
void des3_decrypt_cbc(const char* inputFileName, const char* outputFileName, const unsigned char* key, const unsigned char* iv) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary);

    DES_cblock desKey1, desKey2, desKey3;
    DES_key_schedule ks1, ks2, ks3;

    // Split the 24-byte key into three 8-byte DES keys
    memcpy(desKey1, key, 8);
    memcpy(desKey2, key + 8, 8);
    memcpy(desKey3, key + 16, 8);

    DES_set_key(&desKey1, &ks1);
    DES_set_key(&desKey2, &ks2);
    DES_set_key(&desKey3, &ks3);

    DES_cblock previousCipherBlock;
    memcpy(previousCipherBlock, iv, 8);

    unsigned char inputBlock[8];
    unsigned char outputBlock[8];

    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char*>(inputBlock), 8);

        // Decrypt the block
        DES_ecb3_encrypt((DES_cblock*)inputBlock, (DES_cblock*)outputBlock, &ks1, &ks2, &ks3, DES_DECRYPT);

        // XOR the decrypted block with the previous ciphertext block
        for (int i = 0; i < 8; i++) {
            outputBlock[i] ^= previousCipherBlock[i];
        }

        // Write the plaintext to the output file
        outputFile.write(reinterpret_cast<char*>(outputBlock), 8);

        // Update the previous ciphertext block
        memcpy(previousCipherBlock, inputBlock, 8);
    }

    inputFile.close();
    outputFile.close();
}

int main() {
    const char* inputFileName = "input_image.jpg";
    const char* encryptedFileName = "encrypted_image.jpg";
    const char* decryptedFileName = "decrypted_image.jpg";

    // Generate a random IV
    unsigned char iv[8];
    RAND_bytes(iv, 8);

    // Replace these key values with your own 24-byte 3DES key
    unsigned char key[24];
    RAND_bytes(key, 24);

    // Encrypt the image
    des3_encrypt_cbc(inputFileName, encryptedFileName, key, iv);
    std::cout << "Encryption completed." << std::endl;

    // Decrypt the image
    des3_decrypt_cbc(encryptedFileName, decryptedFileName, key, iv);
    std::cout << "Decryption completed." << std::endl;

    return 0;
}

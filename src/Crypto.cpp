#include "Crypto.h"

// This is the main header for libsodium
#include <sodium.h>

#include <stdexcept> // For std::runtime_error
#include <iostream>  // For error logging

bool Crypto::init() {
    // sodium_init() initializes the library and must be called once.
    // It returns 0 on success, -1 on failure.
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium!" << std::endl;
        return false;
    }
    return true;
}

std::vector<unsigned char> Crypto::encrypt(const std::string& data, const std::string& password) {
    // 1. Generate a random Salt for password hashing (KDF)
    // We use Argon2id, which is the default for crypto_pwhash
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // 2. Derive a 32-byte encryption key from the password and salt
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(
            key, sizeof(key),
            password.c_str(), password.length(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE, // Standard strength
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT // Argon2id
        ) != 0) {
        throw std::runtime_error("Failed to derive encryption key (out of memory?)");
    }

    // 3. Generate a random Nonce (Number used once) for encryption
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 4. Encrypt the data
    // The ciphertext will be slightly longer than the original data
    std::vector<unsigned char> ciphertext(data.length() + crypto_secretbox_MACBYTES);
    
    crypto_secretbox_easy(
        ciphertext.data(),
        (const unsigned char*)data.c_str(), data.length(),
        nonce,
        key
    );

    // 5. Package the data for storage: [SALT][NONCE][CIPHERTEXT]
    // The decrypt function needs all three parts to work.
    std::vector<unsigned char> encrypted_blob;
    encrypted_blob.insert(encrypted_blob.end(), salt, salt + sizeof(salt));
    encrypted_blob.insert(encrypted_blob.end(), nonce, nonce + sizeof(nonce));
    encrypted_blob.insert(encrypted_blob.end(), ciphertext.begin(), ciphertext.end());

    return encrypted_blob;
}

std::optional<std::string> Crypto::decrypt(const std::vector<unsigned char>& encrypted_data, const std::string& password) {
    
    // 1. Check if the data is even long enough to be valid
    if (encrypted_data.size() < crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES) {
        return std::nullopt; // Data is corrupt or invalid
    }

    // 2. Extract the components in the same order we saved them
    const unsigned char* salt = encrypted_data.data();
    const unsigned char* nonce = encrypted_data.data() + crypto_pwhash_SALTBYTES;
    const unsigned char* ciphertext = encrypted_data.data() + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;
    
    size_t ciphertext_len = encrypted_data.size() - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES;

    // 3. Re-derive the *same* encryption key using the *same* salt and password
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(
            key, sizeof(key),
            password.c_str(), password.length(),
            salt, // We use the salt we extracted from the file
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        ) != 0) {
        return std::nullopt; // "Out of memory" is a failure
    }

    // 4. Decrypt the data
    std::vector<unsigned char> decrypted_data(ciphertext_len - crypto_secretbox_MACBYTES);
    
    // crypto_secretbox_open_easy is the magic part.
    // It will *only* succeed if the key, nonce, and ciphertext are all correct.
    // If the password was wrong, the key will be wrong, and this will fail.
    if (crypto_secretbox_open_easy(
            decrypted_data.data(),
            ciphertext, ciphertext_len,
            nonce,
            key
        ) != 0) {
        // This is the normal failure case for a wrong password
        return std::nullopt;
    }

    // 5. Convert the decrypted bytes back to a string
    return std::string((char*)decrypted_data.data(), decrypted_data.size());
}
#pragma once

#include <string>
#include <vector>
#include <optional> // For C++17, to handle decryption failure

// We'll use a namespace since we don't need to store any member variables.
// These are all just utility functions.
namespace Crypto {

    /**
     * @brief Initializes the libsodium library. Must be called once at startup.
     * @return True on success, false on failure.
     */
    bool init();

    /**
     * @brief Encrypts plaintext data using a password.
     * * @param data The plaintext std::string to encrypt.
     * @param password The user's password.
     * @return A vector of bytes containing the encrypted data.
     * Format: [SALT (32 bytes)][NONCE (24 bytes)][CIPHERTEXT]
     */
    std::vector<unsigned char> encrypt(const std::string& data, const std::string& password);

    /**
     * @brief Decrypts an encrypted byte vector using a password.
     * * @param encrypted_data The byte vector from the encrypt function.
     * @param password The user's password.
     * @return A std::optional<std::string>. 
     * If decryption is successful, it contains the plaintext.
     * If it fails (wrong password/corrupt data), it's empty (std::nullopt).
     */
    std::optional<std::string> decrypt(const std::vector<unsigned char>& encrypted_data, const std::string& password);

} // namespace Crypto
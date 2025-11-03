#pragma once

#include <string>
#include <vector>

// Define a structure for a single password entry
struct PasswordEntry {
    // We use a simple timestamp as a unique ID
    uint64_t id; 
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
};

class Vault {
public:
    /**
     * @brief Tries to load and decrypt the vault file from disk.
     * @param filepath The path to the vault file (e.g., "vault.db").
     * @param password The master password.
     * @return True if loading and decryption are successful, false otherwise.
     */
    bool load(const std::string& filepath, const std::string& password);

    /**
     * @brief Encrypts and saves the current vault state to disk.
     * @param filepath The path to the vault file.
     * @param password The master password.
     * @return True on success, false on failure.
     */
    bool save(const std::string& filepath, const std::string& password);

    /**
     * @brief Clears all entries from memory. Used for logging out.
     */
    void clear();

    /**
     * @brief Gets a const reference to the list of entries.
     * This is for the UI to read and display the entries.
     */
    const std::vector<PasswordEntry>& getEntries() const;

    /**
     * @brief Adds a new entry to the vault.
     */
    void addEntry(const PasswordEntry& entry);

    /**
     * @brief Deletes an entry by its unique ID.
     */
    void deleteEntry(uint64_t id);

    /**
     * @brief Gets a mutable pointer to an entry by its ID for editing.
     */
    PasswordEntry* getEntryForEdit(uint64_t id);

private:
    std::vector<PasswordEntry> m_entries;
};
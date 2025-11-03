#include "Vault.h"
#include "Crypto.h" // Our crypto class

// Include the nlohmann JSON library
#include "nlohmann/json.hpp"

#include <fstream>   // For file reading/writing
#include <iostream>  // For error logging

// Use the json alias
using json = nlohmann::json;

// --- JSON Serialization ---
// We need to tell nlohmann-json how to convert
// our PasswordEntry struct to and from JSON.

void to_json(json& j, const PasswordEntry& p) {
    j = json{
        {"id", p.id},
        {"title", p.title},
        {"username", p.username},
        {"password", p.password},
        {"url", p.url},
        {"notes", p.notes}
    };
}

void from_json(const json& j, PasswordEntry& p) {
    j.at("id").get_to(p.id);
    j.at("title").get_to(p.title);
    j.at("username").get_to(p.username);
    j.at("password").get_to(p.password);
    j.at("url").get_to(p.url);
    j.at("notes").get_to(p.notes);
}
// --- End of JSON Serialization ---


bool Vault::load(const std::string& filepath, const std::string& password) {
    // 1. Read the raw encrypted bytes from the file
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Vault file not found. A new one will be created on save." << std::endl;
        return false; // Not an error, just no file to load
    }

    std::vector<unsigned char> encrypted_data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();

    if (encrypted_data.empty()) {
        std::cerr << "Vault file is empty." << std::endl;
        return false;
    }

    // 2. Decrypt the data using our Crypto class
    auto decrypted_json_string = Crypto::decrypt(encrypted_data, password);

    if (!decrypted_json_string) {
        std::cerr << "Failed to decrypt vault (wrong password or corrupt file)." << std::endl;
        return false; // Decryption failed
    }

    // 3. Parse the decrypted JSON string
    try {
        json j = json::parse(*decrypted_json_string);
        m_entries = j.get<std::vector<PasswordEntry>>();
    }
    catch (const json::exception& e) {
        std::cerr << "Failed to parse vault data (file corrupt): " << e.what() << std::endl;
        return false;
    }

    return true; // Success!
}

bool Vault::save(const std::string& filepath, const std::string& password) {
    // 1. Serialize the list of entries into a JSON string
    json j = m_entries;
    std::string json_string = j.dump(4); // dump with 4-space indent

    // 2. Encrypt the JSON string
    std::vector<unsigned char> encrypted_data;
    try {
        encrypted_data = Crypto::encrypt(json_string, password);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to encrypt vault: " << e.what() << std::endl;
        return false;
    }

    // 3. Write the raw encrypted bytes to the file
    std::ofstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open vault file for writing." << std::endl;
        return false;
    }

    file.write((const char*)encrypted_data.data(), encrypted_data.size());
    file.close();

    return true; // Success!
}

void Vault::clear() {
    m_entries.clear();
}

const std::vector<PasswordEntry>& Vault::getEntries() const {
    return m_entries;
}

void Vault::addEntry(const PasswordEntry& entry) {
    m_entries.push_back(entry);
}

void Vault::deleteEntry(uint64_t id) {
    // Find the entry with the matching ID and erase it
    m_entries.erase(
        std::remove_if(m_entries.begin(), m_entries.end(),
            [id](const PasswordEntry& entry) { return entry.id == id; }),
        m_entries.end()
    );
}

PasswordEntry* Vault::getEntryForEdit(uint64_t id) {
    for (auto& entry : m_entries) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}
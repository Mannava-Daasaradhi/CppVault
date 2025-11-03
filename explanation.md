# 📖 C++ Password Vault: Explanation & User Guide

This document explains how to use the C++ Password Vault and how the code is structured.

## Part 1: How to Use the Application (User Guide)

### 1. The First Run & Unlocking

When you first run the app, you will see the "Login to Vault" screen.

* **Vault File:** This defaults to `my_vault.db`. This file does not exist yet.
* **Master Password:** Enter a strong password you will *never* forget.
* **Click "Unlock":** Because `my_vault.db` doesn't exist, the app will log you in and say, "New vault created."

You are now in the main vault. **Your data is not yet saved!**

### 2. Managing Your Passwords

The main screen is split into two parts: the entry list on the left and the details on the right.

* **Add New Entry:**
    1.  Click **"Add New Entry"** at the top.
    2.  This opens the "Add/Edit Entry" popup.
    3.  Fill in the fields.
    4.  Click **"Generate"** to open the Password Generator, create a secure password, and click "Generate & Use."
    5.  Click **"Save"** in the popup.
    6.  Your new entry now appears in the list.

* **Saving Your Vault:**
    * Click the **"Save Vault"** button at the top.
    * This will encrypt all your entries with your master password and save them to the `my_vault.db` file.
    * **This is a manual step!** You must click "Save Vault" to make your changes permanent.

* **Viewing & Editing an Entry:**
    1.  Click any entry in the list on the left.
    2.  The details will appear on the right.
    3.  You can use the **"Copy"** buttons to copy the username or password.
    4.  Click **"Edit"** to open the "Add/Edit Entry" popup and make changes.
    5.  Click **"Save"** in the popup, and then click **"Save Vault"** to save your changes to the file.

### 3. Locking Your Vault

* Click **"Lock Vault"** at the top.
* This will securely clear all vault data from the computer's memory and return you to the login screen.
* To get back in, you must re-enter your master password.

---

## Part 2: Code Architecture (Developer's Guide)

This explains how the different code files work together.

### File Structure

* `src/main.cpp`: The "main" file. It runs the application, manages the UI (using ImGui), and handles the application's state (locked vs. unlocked).
* `src/Crypto.h/.cpp`: The "Security Layer." This file is responsible for *all* cryptographic operations. It knows nothing about vaults or UI.
* `src/Vault.h/.cpp`: The "Data Model." This file manages the list of `PasswordEntry` structs and is responsible for saving/loading the vault from disk.
* `CMakeLists.txt`: The "Build Script." This tells CMake how to find all the libraries and compile the files into a single `.exe`.

### Core Libraries

* **Dear ImGui (with GLFW & GLAD):** A fast and simple graphical user interface library. We use it to draw all the buttons, text boxes, and windows.
* **nlohmann/json:** An easy-to-use C++ library for handling JSON. We use it to convert our `std::vector<PasswordEntry>` into a text string (and back) so we can encrypt it.
* **libsodium:** A modern and secure cryptography library. This is the most important security part.

### How it Works: Class by Class

#### `Crypto.h/.cpp`

This class is the heart of the security model.

* `Crypto::init()`: This **must** be called once when the app starts. It initializes `libsodium`'s random number generator.
* `Crypto::encrypt(data, password)`:
    1.  **Generate a Salt:** Creates a random, 32-byte salt. A salt ensures that even if two users have the same password, their encrypted files will be totally different.
    2.  **Derive a Key:** Uses the **Argon2id** algorithm (the `crypto_pwhash` function) to "mash" the `password` and `salt` together into a single, secure 32-byte encryption key. This is a slow, memory-hard process, which makes it very hard to brute-force.
    3.  **Generate a Nonce:** Creates a random, 24-byte nonce (a "number used once").
    4.  **Encrypt:** Uses the **ChaCha20-Poly1305** algorithm (`crypto_secretbox_easy`) to encrypt the `data` using the `key` and `nonce`.
    5.  **Return a Blob:** It packages everything into one byte vector in this order: `[SALT][NONCE][CIPHERTEXT]`. This is what is saved to the file.

* `Crypto::decrypt(encrypted_blob, password)`:
    1.  **Extract Data:** It "unpacks" the `[SALT]`, `[NONCE]`, and `[CIPHERTEXT]` from the `encrypted_blob`.
    2.  **Re-derive the Key:** It performs the *exact same* **Argon2id** operation using the `password` and the *extracted `[SALT]`*.
    3.  **Decrypt:** It then tries to decrypt the `[CIPHERTEXT]` using the re-derived `key` and the extracted `[NONCE]`.
    4.  **Security Check:** The magic of `crypto_secretbox_open_easy` is that it will **only succeed** if the key is correct. If the password was wrong, the key will be wrong, and the function will fail, returning `std::nullopt`. This is how we know the password was correct.

#### `Vault.h/.cpp`

This class handles the data.

* `PasswordEntry struct`: A simple C++ struct that holds the data for one entry.
* `to_json` / `from_json` functions: These are special functions that tell the `nlohmann/json` library how to convert our `PasswordEntry` struct to a JSON object.
* `Vault::save(filepath, password)`:
    1.  Converts the `m_entries` (a `std::vector<PasswordEntry>`) into a single JSON string.
    2.  Calls `Crypto::encrypt()` on that JSON string, using the master `password`.
    3.  Writes the resulting encrypted byte blob to the `filepath`.
* `Vault::load(filepath, password)`:
    1.  Reads the encrypted byte blob from the `filepath`.
    2.  Calls `Crypto::decrypt()` on that blob, using the master `password`.
    3.  If decryption fails (wrong password), it returns `false`.
    4.  If it succeeds, it parses the decrypted JSON string back into the `m_entries` vector.
    5.  Returns `true`.

#### `main.cpp`

This file ties everything together.

* `AppState`: An `enum` used to control the UI. We show `RenderLoginScreen` if the state is `Locked`, and `RenderMainVault` if it's `Unlocked`.
* `RenderLoginScreen`: Draws the login UI. When "Unlock" is clicked, it calls `vault.load()`. If `vault.load()` returns `true`, it changes the `AppState` to `Unlocked`.
* `RenderMainVault`: Draws the main UI (lists, buttons, etc.).
* `GeneratePassword`: The helper function that uses `libsodium`'s `randombytes_uniform` to securely pick random characters from a character set.
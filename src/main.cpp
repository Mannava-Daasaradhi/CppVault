#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <algorithm>

// GLAD (must be included before GLFW)
#include <glad/glad.h>
#include <GLFW/glfw3.h>

// Dear ImGui
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

// Our custom classes
#include "Crypto.h"
#include <sodium.h> // This also includes <sodium.h> for us
#include "Vault.h"

// --- Application State ---
enum class AppState {
    Locked,
    Unlocked
};

// --- Helper Functions ---
static void glfw_error_callback(int error, const char* description) {
    std::cerr << "Glfw Error " << error << ": " << description << std::endl;
}

uint64_t GetCurrentTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

void CenterWindow(GLFWwindow* window, int display_w, int display_h) {
    ImGui::SetNextWindowSize(ImVec2(700, 500), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2((display_w - 700) * 0.5f, (display_h - 500) * 0.5f), ImGuiCond_FirstUseEver);
}

// --- NEW: Password Generator ---
std::string GeneratePassword(int length, bool use_upper, bool use_lower, bool use_numbers, bool use_symbols) {
    const std::string UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    const std::string NUMBERS = "0123456789";
    const std::string SYMBOLS = "!@#$%^&*()_+-=[]{};:,.<>/?";

    std::string char_set = "";
    if (use_upper) char_set += UPPERCASE;
    if (use_lower) char_set += LOWERCASE;
    if (use_numbers) char_set += NUMBERS;
    if (use_symbols) char_set += SYMBOLS;

    if (char_set.empty()) {
        return "Invalid settings";
    }

    std::string password;
    password.reserve(length);

    for (int i = 0; i < length; ++i) {
        // randombytes_uniform(N) securely generates a number between 0 and N-1
        uint32_t index = randombytes_uniform((uint32_t)char_set.length());
        password += char_set[index];
    }

    return password;
}

// --- Main UI Rendering Functions ---
void RenderLoginScreen(AppState& currentState, Vault& vault, char* passwordBuffer, std::string& vaultFilepath, std::string& loginError) {
    ImGui::Begin("Login to Vault");
    ImGui::Text("Enter Master Password:");
    ImGui::InputText("##Password", passwordBuffer, 128, ImGuiInputTextFlags_Password);
    ImGui::InputText("Vault File", &vaultFilepath[0], 256);

    if (ImGui::Button("Unlock")) {
        if (vault.load(vaultFilepath, passwordBuffer)) {
            currentState = AppState::Unlocked;
            loginError = "";
        }
        else {
            std::ifstream f(vaultFilepath.c_str());
            if (!f.good()) {
                currentState = AppState::Unlocked;
                loginError = "New vault created. Click 'Save' to protect it.";
            } else {
                loginError = "Wrong password or corrupt vault file.";
            }
        }
    }
    if (!loginError.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s", loginError.c_str());
    }
    ImGui::End();
}

void RenderMainVault(AppState& currentState, Vault& vault, char* passwordBuffer, std::string& vaultFilepath, std::string& loginError) {
    static int selectedEntry = -1;
    static PasswordEntry currentEntry;
    static bool showAddEditPopup = false;
    static char filter[128] = "";
    
    // --- NEW: Generator state ---
    static bool showPasswordGenerator = false;
    static int gen_length = 16;
    static bool gen_use_upper = true;
    static bool gen_use_lower = true;
    static bool gen_use_numbers = true;
    static bool gen_use_symbols = true;

    ImGui::Begin("My Vault");

    if (ImGui::Button("Lock Vault")) {
        vault.clear();
        for (int i = 0; i < 128; ++i) passwordBuffer[i] = 0;
        currentState = AppState::Locked;
        loginError = "";
        ImGui::End();
        return;
    }
    ImGui::SameLine();
    if (ImGui::Button("Save Vault")) {
        if (!vault.save(vaultFilepath, passwordBuffer)) {
            loginError = "Failed to save vault!";
        } else {
            loginError = "Vault saved successfully.";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Add New Entry")) {
        currentEntry = PasswordEntry();
        currentEntry.id = GetCurrentTimeMillis();
        showAddEditPopup = true;
        ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_Appearing);
        ImGui::OpenPopup("Add/Edit Entry");
    }

    if (!loginError.empty()) {
        ImGui::Text("%s", loginError.c_str());
    }

    ImGui::Separator();
    ImGui::InputText("Filter", filter, IM_ARRAYSIZE(filter));
    ImGui::Separator();

    // --- Left Pane (Entry List) ---
    ImGui::BeginChild("EntryList", ImVec2(200, 0), true);
    int entry_n = 0;
    for (const auto& entry : vault.getEntries()) {
        std::string filterLower = filter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);
        std::string titleLower = entry.title;
        std::transform(titleLower.begin(), titleLower.end(), titleLower.begin(), ::tolower);
        
        if (filter[0] == '\0' || titleLower.find(filterLower) != std::string::npos) {
            if (ImGui::Selectable(entry.title.c_str(), selectedEntry == entry_n)) {
                selectedEntry = entry_n;
            }
        }
        entry_n++;
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // --- Right Pane (Entry Details) ---
    ImGui::BeginChild("EntryDetails", ImVec2(0, 0), true);
    if (selectedEntry != -1 && selectedEntry < vault.getEntries().size()) {
        const auto& entry = vault.getEntries()[selectedEntry];
        
        ImGui::Text("Title: %s", entry.title.c_str());
        ImGui::Separator();
        
        ImGui::Text("Username:");
        ImGui::InputText("##Username", (char*)entry.username.c_str(), entry.username.size(), ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine(); if (ImGui::Button("Copy##user")) ImGui::SetClipboardText(entry.username.c_str());
        
        ImGui::Text("Password:");
        ImGui::InputText("##Password", (char*)entry.password.c_str(), entry.password.size(), ImGuiInputTextFlags_Password | ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine(); if (ImGui::Button("Copy##pass")) ImGui::SetClipboardText(entry.password.c_str());

        ImGui::Text("URL: %s", entry.url.c_str());
        ImGui::Text("Notes:\n%s", entry.notes.c_str());

        ImGui::Separator();
        if (ImGui::Button("Edit")) {
            currentEntry = entry;
            showAddEditPopup = true;
            ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_Appearing);
            ImGui::OpenPopup("Add/Edit Entry");
        }
        ImGui::SameLine();
        if (ImGui::Button("Delete")) {
            vault.deleteEntry(entry.id);
            selectedEntry = -1;
        }
    } else {
        ImGui::Text("Select an entry to view details.");
    }
    ImGui::EndChild();

    // --- Add/Edit Popup Modal ---
    if (ImGui::BeginPopupModal("Add/Edit Entry", &showAddEditPopup)) {
        static char titleBuf[128], userBuf[128], passBuf[128], urlBuf[256], notesBuf[512];
        
        if (showAddEditPopup) {
            strncpy(titleBuf, currentEntry.title.c_str(), sizeof(titleBuf) - 1);
            strncpy(userBuf, currentEntry.username.c_str(), sizeof(userBuf) - 1);
            strncpy(passBuf, currentEntry.password.c_str(), sizeof(passBuf) - 1);
            strncpy(urlBuf, currentEntry.url.c_str(), sizeof(urlBuf) - 1);
            strncpy(notesBuf, currentEntry.notes.c_str(), sizeof(notesBuf) - 1);
            showAddEditPopup = false;
        }
        
        ImGui::InputText("Title", titleBuf, IM_ARRAYSIZE(titleBuf));
        ImGui::InputText("Username", userBuf, IM_ARRAYSIZE(userBuf));
        
        // --- NEW: Add "Generate" button next to password ---
        ImGui::InputText("Password", passBuf, IM_ARRAYSIZE(passBuf));
        ImGui::SameLine();
        if (ImGui::Button("Generate")) {
            showPasswordGenerator = true;
            ImGui::OpenPopup("Password Generator");
        }
        // --- End NEW ---

        ImGui::InputText("URL", urlBuf, IM_ARRAYSIZE(urlBuf));
        ImGui::InputTextMultiline("Notes", notesBuf, IM_ARRAYSIZE(notesBuf));

        if (ImGui::Button("Save")) {
            currentEntry.title = titleBuf;
            currentEntry.username = userBuf;
            currentEntry.password = passBuf;
            currentEntry.url = urlBuf;
            currentEntry.notes = notesBuf;

            PasswordEntry* existing = vault.getEntryForEdit(currentEntry.id);
            if (existing) {
                *existing = currentEntry;
            } else {
                vault.addEntry(currentEntry);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }

        // --- NEW: Password Generator Popup ---
        if (ImGui::BeginPopupModal("Password Generator", &showPasswordGenerator)) {
            ImGui::Text("Password Options");
            ImGui::Separator();
            ImGui::SliderInt("Length", &gen_length, 8, 128);
            ImGui::Checkbox("Uppercase (A-Z)", &gen_use_upper);
            ImGui::Checkbox("Lowercase (a-z)", &gen_use_lower);
            ImGui::Checkbox("Numbers (0-9)", &gen_use_numbers);
            ImGui::Checkbox("Symbols (!@#...)", &gen_use_symbols);
            ImGui::Separator();

            if (ImGui::Button("Generate & Use")) {
                std::string new_pass = GeneratePassword(gen_length, gen_use_upper, gen_use_lower, gen_use_numbers, gen_use_symbols);
                // Copy the new password into the Add/Edit buffer
                strncpy(passBuf, new_pass.c_str(), sizeof(passBuf) - 1);
                passBuf[sizeof(passBuf) - 1] = 0; // Ensure null termination
                showPasswordGenerator = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                showPasswordGenerator = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
        // --- End NEW ---

        ImGui::EndPopup();
    }

    ImGui::End();
}

// --- Main Function ---
int main(int, char**) {
    // --- 0. Initialize Libsodium ---
    if (!Crypto::init()) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized successfully." << std::endl;

    // --- 1. Setup GLFW (Windowing) ---
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    GLFWwindow* window = glfwCreateWindow(1280, 720, "C++ Password Vault", NULL, NULL);
    if (window == NULL) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // --- 2. Setup GLAD (OpenGL) ---
    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) {
        std::cerr << "Failed to initialize GLAD" << std::endl;
        return 1;
    }

    // --- 3. Setup Dear ImGui ---
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // --- 4. Application State Variables ---
    AppState currentState = AppState::Locked;
    Vault vault;
    std::string vaultFilepath = "my_vault.db";
    char passwordBuffer[128] = { 0 };
    std::string loginError = "";
    
    // --- Main loop ---
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // --- 5. Render UI based on state ---
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        CenterWindow(window, display_w, display_h);

        if (currentState == AppState::Locked) {
            RenderLoginScreen(currentState, vault, passwordBuffer, vaultFilepath, loginError);
        } else {
            RenderMainVault(currentState, vault, passwordBuffer, vaultFilepath, loginError);
        }

        // --- 6. Rendering ---
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // --- 7. Cleanup ---
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
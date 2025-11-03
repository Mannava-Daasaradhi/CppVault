# Set the minimum CMake version
cmake_minimum_required(VERSION 3.18)

# Set the project name
project(CppVault VERSION 1.0)

# Set the C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# --- Find All Our Dependencies ---
# We tell find_package to look for the libraries vcpkg installed.

# 1. Crypto Library (Using the name from vcpkg output)
find_package(unofficial-sodium CONFIG REQUIRED)

# 2. JSON Library
find_package(nlohmann_json 3.2.0 REQUIRED)

# 3. GUI Library
find_package(imgui CONFIG REQUIRED)

# 4. Windowing Library
find_package(glfw3 3.3 REQUIRED)

# 5. OpenGL Loader
find_package(glad CONFIG REQUIRED)

# --- Define Our Executable ---
# This creates the final .exe or binary file from our source code
# --- Define Our Executable ---
# --- Define Our Executable ---
add_executable(CppVault
    src/main.cpp
    src/Crypto.cpp
    src/Vault.cpp
)

# --- Link All Libraries ---
# This tells the compiler to "link" the libraries to our executable
target_link_libraries(CppVault PRIVATE
    # Crypto (Matching vcpkg output exactly, with hyphen)
    unofficial-sodium::sodium

    # JSON
    nlohmann_json::nlohmann_json

    # GUI
    imgui::imgui

    # Windowing & Rendering
    glfw
    glad::glad
)
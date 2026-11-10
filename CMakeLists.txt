cmake_minimum_required(VERSION 3.21)
project(SecureSpace VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# libsodium: pkg-config (Linux / macOS / MSYS2) o vcpkg (Windows)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()
if(TARGET PkgConfig::SODIUM)
  set(SS_SODIUM_TARGET PkgConfig::SODIUM)
else()
  find_package(unofficial-sodium CONFIG REQUIRED)
  set(SS_SODIUM_TARGET unofficial-sodium::sodium)
endif()

# MSVC parses vector<T> value(std::size_t(expr)); as a function declaration (the
# most-vexing parse). Generate the build input with an unambiguous size/value
# constructor so the vectors and downstream libsodium calls are compiled correctly.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/Vault.cpp" SS_VAULT_CPP)
string(REPLACE
  "std::vector<unsigned char> plain(std::size_t(kChunk));"
  "std::vector<unsigned char> plain(static_cast<std::size_t>(kChunk), 0);"
  SS_VAULT_CPP "${SS_VAULT_CPP}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/Vault.cpp" "${SS_VAULT_CPP}")

add_executable(SecureSpace WIN32 MACOSX_BUNDLE
  src/main.cpp
  src/Theme.cpp
  "${CMAKE_CURRENT_BINARY_DIR}/Vault.cpp"
  src/AuthDialogs.cpp
  src/MainWindow.cpp
  src/SettingsDialog.cpp
)
target_include_directories(SecureSpace PRIVATE src)
target_link_libraries(SecureSpace PRIVATE Qt6::Widgets ${SS_SODIUM_TARGET})

if(MSVC)
  target_compile_options(SecureSpace PRIVATE /W4 /utf-8 /permissive-)
else()
  target_compile_options(SecureSpace PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()

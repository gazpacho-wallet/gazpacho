cmake_minimum_required(VERSION 3.14)
project(gazpacho_import VERSION 0.0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# Extensions stay ON (gnu11), exactly as in SuperScalar's own build: bip39.c uses strtok_r.
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GZ_SANITIZE "Build everything (including secp256k1-zkp) with AddressSanitizer + UBSan" OFF)
if(GZ_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# --- secp256k1-zkp at the exact commit SuperScalar pins, same modules ---------
# Mirrors SuperScalar CMakeLists.txt lines 80-95. tools/update-import.sh checks this tag
# against the pinned SuperScalar commit's CMakeLists.txt.
include(FetchContent)
# Static secp256k1 (SuperScalar CMakeLists.txt line 76 does the same).
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG      ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS  ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY   ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS            OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK        OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES         OFF CACHE BOOL "" FORCE)
FetchContent_Declare(secp256k1-zkp
  GIT_REPOSITORY https://github.com/BlockstreamResearch/secp256k1-zkp.git
  GIT_TAG        6152622613fdf1c5af6f31f74c427c4e9ee120ce
)
FetchContent_MakeAvailable(secp256k1-zkp)

find_package(OpenSSL REQUIRED)   # libcrypto only is used

# --- imported SuperScalar files (unchanged) + shims ---------------------------
set(SS ${CMAKE_CURRENT_SOURCE_DIR}/core/superscalar)
file(GLOB GZ_SS_SOURCES CONFIGURE_DEPENDS ${SS}/src/*.c)
file(GLOB GZ_SHIM_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/shim/*.c)

add_library(gazpacho_superscalar STATIC ${GZ_SS_SOURCES} ${GZ_SHIM_SOURCES})
target_include_directories(gazpacho_superscalar
  PUBLIC  ${SS}/include
  PRIVATE ${SS}/src ${CMAKE_CURRENT_SOURCE_DIR}/core/shim)
target_link_libraries(gazpacho_superscalar PUBLIC secp256k1 OpenSSL::Crypto)
target_compile_options(gazpacho_superscalar PRIVATE -Wall -Wextra)

# --- tests -------------------------------------------------------------------
enable_testing()
add_executable(test_reference_tree tests/test_reference_tree.c)
target_link_libraries(test_reference_tree PRIVATE gazpacho_superscalar)
target_compile_options(test_reference_tree PRIVATE -Wall -Wextra)
target_compile_definitions(test_reference_tree PRIVATE
  GZ_REFERENCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/tests/reference/superscalar-tree-txids.txt")
add_test(NAME reference_tree
  COMMAND test_reference_tree ${CMAKE_CURRENT_SOURCE_DIR}/tests/reference/superscalar-tree-txids.txt)

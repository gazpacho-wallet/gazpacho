# Storage encryption (spec/storage-encryption.md draft 3, Slice 1 subset).
# Outside the I/O-free core: libsodium is linked here and in programs only,
# never into gazpacho_core (spec 13; the storage_core_has_no_sodium test).
#
# Dependencies, each pinned by SHA-256 and fetched at configure/build time, or
# taken from GZ_DEPS_DIR when that folder holds the same file:
#   libsodium 1.0.22, the signed release tarball. Its minisign signature
#     (key RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3, the one
#     on doc.libsodium.org) was checked when the hash was pinned:
#     tools/verify-libsodium.sh repeats the check; docs/notes/storage-crypto.md
#     records it.
#   utf8proc 2.12.0 (MIT), for NFC (spec 4.1, open point 2).
include(ExternalProject)

set(GZ_DEPS_DIR "" CACHE PATH "Optional folder holding the pinned dependency tarballs")

set(GZ_SODIUM_VERSION 1.0.22)
set(GZ_SODIUM_SHA256 adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349)
set(GZ_UTF8PROC_VERSION 2.12.0)
set(GZ_UTF8PROC_SHA256 f564011d38b2888d583d510b08e69ffa15aa117155db1b9b49ef1dfe1fa25111)

set(_sodium_tar libsodium-${GZ_SODIUM_VERSION}.tar.gz)
if(GZ_DEPS_DIR AND EXISTS ${GZ_DEPS_DIR}/${_sodium_tar})
  set(_sodium_urls ${GZ_DEPS_DIR}/${_sodium_tar})
else()
  set(_sodium_urls
    https://download.libsodium.org/libsodium/releases/${_sodium_tar}
    https://github.com/jedisct1/libsodium/releases/download/${GZ_SODIUM_VERSION}-RELEASE/${_sodium_tar})
endif()

# libsodium is built with the same compiler and C flags as everything else,
# so MemorySanitizer and the fuzz build instrument it too. Assembly is off:
# MSan cannot see what assembly writes; none of it is used here.
string(TOUPPER "${CMAKE_BUILD_TYPE}" _bt)
set(_sodium_cflags "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_bt}}")
# Under MemorySanitizer, libsodium's SIMD code paths (chosen at run time by
# CPU detection) use intrinsics MSan does not model, and it reports Argon2's
# output as uninitialised. Automake puts CPPFLAGS after the configure-time
# -D definitions, so -U here leaves only the portable reference code. No
# documented configure option does this: --disable-asm covers assembly files
# only, and 1.0.22's other switches (ssp, pie, blocking-random, minimal,
# pthreads, safecode, ctgrind, retpoline, debug, opt, soname-versions) do not
# touch the intrinsics. The names are those configure.ac defines.
set(_sodium_cppflags "")
if(CMAKE_C_FLAGS MATCHES "-fsanitize=memory")
  set(_sodium_cppflags "-UHAVE_MMINTRIN_H -UHAVE_EMMINTRIN_H -UHAVE_PMMINTRIN_H -UHAVE_TMMINTRIN_H -UHAVE_SMMINTRIN_H -UHAVE_AVXINTRIN_H -UHAVE_AVX2INTRIN_H -UHAVE_AVX512FINTRIN_H -UHAVE_WMMINTRIN_H -UHAVE_RDRAND -UHAVE_ARMCRYPTO")
endif()
set(_sodium_prefix ${CMAKE_BINARY_DIR}/libsodium)
set(_sodium_lib ${_sodium_prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX})
ExternalProject_Add(libsodium_ext
  URL ${_sodium_urls}
  URL_HASH SHA256=${GZ_SODIUM_SHA256}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  PREFIX ${CMAKE_BINARY_DIR}/libsodium-build
  INSTALL_DIR ${_sodium_prefix}
  CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --libdir=<INSTALL_DIR>/lib
    --disable-shared --enable-static --with-pic --disable-asm --disable-dependency-tracking
    --disable-silent-rules
    CC=${CMAKE_C_COMPILER} "CFLAGS=${_sodium_cflags}" "CPPFLAGS=${_sodium_cppflags}"
    "LDFLAGS=${CMAKE_EXE_LINKER_FLAGS}"
  BUILD_COMMAND $(MAKE)
  INSTALL_COMMAND $(MAKE) install
  BUILD_BYPRODUCTS ${_sodium_lib}
  LOG_CONFIGURE TRUE LOG_BUILD TRUE LOG_INSTALL TRUE LOG_OUTPUT_ON_FAILURE TRUE)
file(MAKE_DIRECTORY ${_sodium_prefix}/include)
add_library(gz_sodium STATIC IMPORTED GLOBAL)
set_target_properties(gz_sodium PROPERTIES
  IMPORTED_LOCATION ${_sodium_lib}
  INTERFACE_INCLUDE_DIRECTORIES ${_sodium_prefix}/include)
add_dependencies(gz_sodium libsodium_ext)

include(FetchContent)
set(_u8_tar utf8proc-${GZ_UTF8PROC_VERSION}.tar.gz)
if(GZ_DEPS_DIR AND EXISTS ${GZ_DEPS_DIR}/${_u8_tar})
  set(_u8_url ${GZ_DEPS_DIR}/${_u8_tar})
else()
  set(_u8_url https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v${GZ_UTF8PROC_VERSION}.tar.gz)
endif()
set(UTF8PROC_INSTALL OFF CACHE BOOL "" FORCE)
set(UTF8PROC_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(utf8proc URL ${_u8_url} URL_HASH SHA256=${GZ_UTF8PROC_SHA256}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(utf8proc)

set(GZ_SC_SOURCES sc_core.c sc_keyfile.c sc_journal.c sc_export.c sc_misc.c sc_pass.c sc_wordlist.c
                  sc_kdf.c sc_files.c)
set(GZ_SC_WARNINGS -Wall -Wextra -Werror -Wvla -Wshadow -Wconversion -Wno-sign-conversion)

function(gz_sc_library name)
  add_library(${name} STATIC ${GZ_SC_SOURCES})
  set_target_properties(${name} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(${name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                     PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${name} PUBLIC gz_sodium utf8proc)
  target_compile_options(${name} PRIVATE ${GZ_SC_WARNINGS})
  add_dependencies(${name} libsodium_ext)
endfunction()

# The release library: no test entry point (4.2, F24).
gz_sc_library(gazpacho_storage_crypto)
target_compile_options(gazpacho_storage_crypto PRIVATE -pedantic)
# The test library: the test hooks of gz_storage_crypto_test.h.
gz_sc_library(gazpacho_storage_crypto_test)
target_compile_definitions(gazpacho_storage_crypto_test PUBLIC GZ_SC_TEST_ENTRY)
target_compile_options(gazpacho_storage_crypto_test PRIVATE -pedantic)

option(GZ_SC_TESTS "Build and register the storage encryption tests" ON)
if(GZ_SC_TESTS)
  set(T ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  # The helper programs: the test KDF helper (the program's hidden mode on
  # the test library; GZ_SC_TEST_FLOOR lowers its floor for the vectors) and
  # one that crashes, one that answers short.
  add_executable(sc_kdf_helper ${T}/kdf_helper.c)
  target_link_libraries(sc_kdf_helper PRIVATE gazpacho_storage_crypto_test)
  target_compile_options(sc_kdf_helper PRIVATE ${GZ_SC_WARNINGS})
  add_executable(sc_bad_helper ${T}/bad_helper.c)
  target_compile_options(sc_bad_helper PRIVATE ${GZ_SC_WARNINGS})

  foreach(t vectors formats files)
    add_executable(sc_test_${t} ${T}/test_${t}.c ${T}/sc_test.c)
    target_link_libraries(sc_test_${t} PRIVATE gazpacho_storage_crypto_test)
    target_include_directories(sc_test_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(sc_test_${t} PRIVATE ${GZ_SC_WARNINGS})
    target_compile_definitions(sc_test_${t} PRIVATE
      GZ_SC_HELPER="$<TARGET_FILE:sc_kdf_helper>" GZ_SC_BAD_HELPER="$<TARGET_FILE:sc_bad_helper>")
    add_dependencies(sc_test_${t} sc_kdf_helper sc_bad_helper)
    add_test(NAME storage_${t} COMMAND sc_test_${t})
  endforeach()
  # E2r: Argon2id at the real 256 MiB. Under valgrind it is left out (CI's
  # valgrind job excludes it): it is the same code as E2 at more memory.
  add_test(NAME storage_vector_e2r COMMAND sc_test_vectors e2r)
  # Test 29 (F24): the release library refuses E2's key file before deriving.
  add_executable(sc_test_release ${T}/test_release.c)
  target_link_libraries(sc_test_release PRIVATE gazpacho_storage_crypto)
  target_compile_options(sc_test_release PRIVATE ${GZ_SC_WARNINGS})
  add_test(NAME storage_release_refuses_test_params COMMAND sc_test_release)
  add_test(NAME storage_release_has_no_test_entry
    COMMAND sh ${T}/check-symbols.sh no-test-entry $<TARGET_FILE:gazpacho_storage_crypto>)
  add_test(NAME storage_core_has_no_sodium
    COMMAND sh ${T}/check-symbols.sh no-sodium $<TARGET_FILE:gazpacho_core>)

  # Fuzz targets (one per parser): plain driver as CTest tests, or libFuzzer
  # with -DGZ_LIBFUZZER=ON (tools/run-fuzz.sh runs every fuzz_*).
  foreach(f sc_keyfile sc_frame sc_mark sc_export)
    if(GZ_LIBFUZZER)
      add_executable(fuzz_${f} ${T}/fuzz_${f}.c)
      target_link_options(fuzz_${f} PRIVATE -fsanitize=fuzzer)
    else()
      add_executable(fuzz_${f} ${T}/fuzz_${f}.c ${T}/fuzz_main.c)
      add_test(NAME storage_fuzz_${f} COMMAND fuzz_${f} 20000)
    endif()
    target_link_libraries(fuzz_${f} PRIVATE gazpacho_storage_crypto_test)
    target_compile_options(fuzz_${f} PRIVATE ${GZ_SC_WARNINGS})
  endforeach()

  # Constant time where secrets meet branches (valgrind, as libsecp256k1's
  # ctime tests): a library copy with SC_DECLASSIFY, run under memcheck with
  # every secret marked undefined. Registered only where valgrind is found;
  # CI's valgrind job runs it (it is not in tools/valgrind-tests.py's list,
  # since its command is valgrind itself).
  include(CheckIncludeFile)
  check_include_file(valgrind/memcheck.h GZ_HAVE_MEMCHECK_H)
  find_program(GZ_VALGRIND valgrind)
  if(GZ_HAVE_MEMCHECK_H)
    gz_sc_library(gazpacho_storage_crypto_ctime)
    target_compile_definitions(gazpacho_storage_crypto_ctime PUBLIC GZ_SC_TEST_ENTRY GZ_SC_CTIME)
    add_executable(sc_test_ctime ${T}/test_ctime.c)
    target_link_libraries(sc_test_ctime PRIVATE gazpacho_storage_crypto_ctime)
    target_include_directories(sc_test_ctime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(sc_test_ctime PRIVATE ${GZ_SC_WARNINGS})
    # Not with a sanitizer: valgrind cannot run a sanitized program.
    if(GZ_VALGRIND AND NOT GZ_SANITIZE AND NOT CMAKE_C_FLAGS MATCHES "-fsanitize")
      add_test(NAME storage_ctime
        COMMAND ${GZ_VALGRIND} --error-exitcode=42 --track-origins=yes
                --suppressions=${T}/ctime.supp $<TARGET_FILE:sc_test_ctime>)
    endif()
  endif()
endif()

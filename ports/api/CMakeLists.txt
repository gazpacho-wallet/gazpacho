# The local API server (spec/local-api.md draft 4) and its tests.
find_package(Threads REQUIRED)

# --- llhttp, vendored unchanged and pinned by SHA-256 (third_party/llhttp/IMPORT.md) ---
# Its own warnings are not ours to fix: no -Werror here, and the files are
# never edited (tools/check-llhttp.sh compares them with the pins).
add_library(gazpacho_llhttp STATIC
  third_party/llhttp/src/api.c
  third_party/llhttp/src/http.c
  third_party/llhttp/src/llhttp.c)
target_include_directories(gazpacho_llhttp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llhttp/include)
set_target_properties(gazpacho_llhttp PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)

# --- the server -------------------------------------------------------------------
# Strict C11 like the transport, POSIX and Linux calls named per file.
add_library(gazpacho_api STATIC
  json.c util.c http.c route.c session.c derive.c events.c status.c peer.c static.c server.c)
set_target_properties(gazpacho_api PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_include_directories(gazpacho_api
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gazpacho_api PUBLIC gazpacho_llhttp OpenSSL::Crypto Threads::Threads)
target_compile_options(gazpacho_api PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

# --- TEST ONLY: the fake backend, for the tests and gz-api-fake, never the program ---
add_library(gazpacho_api_fake STATIC fake/fake_backend.c)
set_target_properties(gazpacho_api_fake PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_compile_definitions(gazpacho_api_fake PUBLIC GZ_API_FAKE_BACKEND)
target_include_directories(gazpacho_api_fake PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fake)
target_link_libraries(gazpacho_api_fake PUBLIC gazpacho_api)
target_compile_options(gazpacho_api_fake PRIVATE ${GZ_NEW_CODE_WARNINGS} -pedantic -Wvla)

add_executable(gz-api-fake ${PROJECT_SOURCE_DIR}/tools/gz-api-fake/main.c)
target_link_libraries(gz-api-fake PRIVATE gazpacho_api_fake)
target_compile_options(gz-api-fake PRIVATE ${GZ_NEW_CODE_WARNINGS})

# --- tests ---------------------------------------------------------------------
set(API_TESTS ${PROJECT_SOURCE_DIR}/tests/api)
function(gz_api_test name)
  add_executable(test_api_${name} ${API_TESTS}/test_${name}.c)
  target_link_libraries(test_api_${name} PRIVATE gazpacho_api_fake)
  target_include_directories(test_api_${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/tests)
  target_compile_options(test_api_${name} PRIVATE ${GZ_NEW_CODE_WARNINGS})
  add_test(NAME api_${name} COMMAND test_api_${name} ${ARGN})
  set_tests_properties(api_${name} PROPERTIES LABELS api)
endfunction()

gz_api_test(json)
gz_api_test(status)
gz_api_test(server)
gz_api_test(peer)

# The end-to-end run: Python's http.client against gz-api-fake.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_test(NAME api_e2e_fake
    COMMAND ${Python3_EXECUTABLE} -I ${API_TESTS}/e2e_fake.py $<TARGET_FILE:gz-api-fake>)
  set_tests_properties(api_e2e_fake PROPERTIES LABELS api TIMEOUT 300)
  # The C test's copy of vector E15 is the specification's.
  add_test(NAME api_e15_vector COMMAND ${Python3_EXECUTABLE} -I ${PROJECT_SOURCE_DIR}/tools/api-e15-vector.py --check)
  set_tests_properties(api_e15_vector PROPERTIES LABELS api)
endif()

# Fuzz targets: the request parser with routing and every check, and the
# JSON parser with the canonical form. Plain driver as CTest tests normally;
# libFuzzer with -DGZ_LIBFUZZER=ON (tools/run-fuzz.sh, the CI fuzz job).
foreach(target api_http api_json)
  if(GZ_LIBFUZZER)
    add_executable(fuzz_${target} ${API_TESTS}/fuzz_${target}.c)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  else()
    add_executable(fuzz_${target} ${API_TESTS}/fuzz_${target}.c ${PROJECT_SOURCE_DIR}/tests/net/fuzz_main.c)
    add_test(NAME ${target}_fuzz COMMAND fuzz_${target} 20000)
    set_tests_properties(${target}_fuzz PROPERTIES LABELS api)
  endif()
  target_link_libraries(fuzz_${target} PRIVATE gazpacho_api_fake)
  target_include_directories(fuzz_${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(fuzz_${target} PRIVATE ${GZ_NEW_CODE_WARNINGS})
endforeach()

# The vendored parser has not changed.
add_test(NAME api_llhttp_pinned
  COMMAND sh ${PROJECT_SOURCE_DIR}/tools/check-llhttp.sh ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llhttp)
set_tests_properties(api_llhttp_pinned PROPERTIES LABELS api)

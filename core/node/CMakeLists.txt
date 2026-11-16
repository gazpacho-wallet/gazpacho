# The composite node (docs/notes/composite-node.md). Strict C11, freestanding,
# with the core's flags: the isolation check covers it like any core library
# (its tests are registered in the top-level CMakeLists.txt).
#
#   gazpacho_node       release: the node part alone (the lobby comes in P4.2)
#   gazpacho_node_test  GZ_TEST_KINDS: the test engine (the old placeholder
#                       ping, areas 0x7e57 and 0x7e58) and the slot stand-in
set(GZ_NODE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/composite.c
  ${CMAKE_CURRENT_SOURCE_DIR}/handoff.c
  ${CMAKE_CURRENT_SOURCE_DIR}/route.c
  ${CMAKE_CURRENT_SOURCE_DIR}/timers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/watches.c
  ${CMAKE_CURRENT_SOURCE_DIR}/nodepart.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_engine.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_slot.c
  PARENT_SCOPE)
set(GZ_NODE_SOURCES_HERE
  composite.c handoff.c route.c timers.c watches.c nodepart.c test_engine.c test_slot.c)

foreach(variant release test)
  if(variant STREQUAL "release")
    set(lib gazpacho_node)
  else()
    set(lib gazpacho_node_test)
  endif()
  add_library(${lib} STATIC ${GZ_NODE_SOURCES_HERE})
  set_target_properties(${lib} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(${lib} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${lib} PUBLIC gazpacho_core)
  target_compile_options(${lib} PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
  if(variant STREQUAL "test")
    target_compile_definitions(${lib} PRIVATE GZ_TEST_KINDS)
  endif()
endforeach()

# For the isolation check: the core and the node in one archive each, so that
# the node's calls into the core are calls inside the library.
foreach(variant release test)
  set(lib gazpacho_node_isolation_${variant})
  add_library(${lib} STATIC ${GZ_NODE_SOURCES_HERE}
              ${CMAKE_SOURCE_DIR}/core/gazpacho/action.c ${CMAKE_SOURCE_DIR}/core/gazpacho/runner.c
              ${CMAKE_SOURCE_DIR}/core/gazpacho/envelope.c)
  set_target_properties(${lib} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(${lib} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}
                                            ${CMAKE_SOURCE_DIR}/core/gazpacho/include)
  target_compile_options(${lib} PRIVATE ${GZ_NEW_CODE_WARNINGS} ${GZ_CORE_FLAGS})
  if(variant STREQUAL "test")
    target_compile_definitions(${lib} PRIVATE GZ_TEST_KINDS)
  endif()
endforeach()

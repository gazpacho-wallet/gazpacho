# K20 at configure time and in every built program (review A of #71, H3 and
# N1). Included at the end of the top-level CMakeLists.txt, once every
# directory has been added.
#
# 1. Only the signer's own vectors test may link gazpacho_signer_vectors, the
#    one build that accepts fixed aux_rand. Every target of every directory
#    is checked: its direct and interface link libraries, each entry compared
#    as a substring, so a generator expression such as
#    $<TARGET_FILE:gazpacho_signer_vectors> counts too. A library that links
#    it is refused as well, so it cannot reach a program transitively.
#    (An ALIAS of it, a -DGZ_SG_VECTORS flag or a list of signer/ sources in
#    a build file outside signer/ is refused by tools/check-signer-boundary.sh.)
# 2. signer_never_ship (CTest): every executable the build makes, except the
#    test and fuzz programs, is read with nm after the build and must not hold
#    the marker gz_sg_vectors_build_never_ship. This sees the vectors build
#    however it got in, flags and copied sources included.

set(GZ_SIGNER_SHIPPED "")

function(gz_signer_vectors_guard dir)
  get_property(targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
  foreach(t IN LISTS targets)
    get_target_property(type ${t} TYPE)
    set(libs "")
    if(NOT type STREQUAL "INTERFACE_LIBRARY")
      get_target_property(direct ${t} LINK_LIBRARIES)
      if(direct)
        list(APPEND libs ${direct})
      endif()
    endif()
    get_target_property(iface ${t} INTERFACE_LINK_LIBRARIES)
    if(iface)
      list(APPEND libs ${iface})
    endif()
    foreach(l IN LISTS libs)
      string(FIND "${l}" "gazpacho_signer_vectors" at)
      if(NOT at EQUAL -1 AND NOT t STREQUAL "test_signer_vectors")
        message(FATAL_ERROR "${t} links gazpacho_signer_vectors (${l}), the fixed-aux test build of the signer: "
                            "only test_signer_vectors may (docs/notes/signer.md, decision K20)")
      endif()
    endforeach()
    # a program that is not a test or fuzz target is shipped, or could be
    # (the fetched dependencies' own programs, and any not built by default,
    # are not ours to ship)
    get_target_property(src ${t} SOURCE_DIR)
    get_target_property(excluded ${t} EXCLUDE_FROM_ALL)
    if(type STREQUAL "EXECUTABLE" AND NOT t MATCHES "^(test_|fuzz_)" AND NOT excluded
       AND NOT src MATCHES "/_deps/" AND NOT src MATCHES "^${CMAKE_BINARY_DIR}")
      set_property(GLOBAL APPEND PROPERTY GZ_SIGNER_SHIPPED_TARGETS ${t})
    endif()
  endforeach()
  get_property(subdirs DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)
  foreach(d IN LISTS subdirs)
    gz_signer_vectors_guard(${d})
  endforeach()
endfunction()
gz_signer_vectors_guard(${CMAKE_CURRENT_SOURCE_DIR})

get_property(gz_shipped GLOBAL PROPERTY GZ_SIGNER_SHIPPED_TARGETS)
set(gz_shipped_files "")
foreach(t IN LISTS gz_shipped)
  list(APPEND gz_shipped_files $<TARGET_FILE:${t}>)
endforeach()
add_test(NAME signer_never_ship
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/signer/tests/never_ship.sh ${gz_shipped_files})
# The check itself sees the marker where it is: the vectors test program.
add_test(NAME signer_never_ship_sees_marker
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/signer/tests/never_ship.sh --expect-marker $<TARGET_FILE:test_signer_vectors>)

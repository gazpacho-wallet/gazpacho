# slice1-attempt: the glue program (throwaway, never merged)
add_executable(gazpacho-slice1 s1_main.c s1_lobby.c s1_sign.c s1_fund.c)
target_include_directories(gazpacho-slice1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/ports/net
                           ${secp256k1-zkp_SOURCE_DIR}/include)
target_link_libraries(gazpacho-slice1 PRIVATE gazpacho_lobby gazpacho_signing gazpacho_tree_import gazpacho_tree
                      gazpacho_net_testkinds gazpacho_wallet_tx gazpacho_chain_curl gazpacho_core secp256k1)
target_compile_options(gazpacho-slice1 PRIVATE -Wall -Wextra)

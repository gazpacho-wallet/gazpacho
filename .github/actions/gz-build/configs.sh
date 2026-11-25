# The builds CI makes, one name each, for .github/actions/gz-build. Sourced
# by bash: gz_config NAME sets
#   PKGS        the Ubuntu packages the build and its tests need
#   COMPILER    the C compiler, exported as CC when it is not the default gcc
#   BUILD_TYPE  CMAKE_BUILD_TYPE
#   SANITIZER   none, asan, msan or fuzz (part of the ccache key only)
#   CMAKE_ARGS  the configure options (an array), CMAKE_BUILD_TYPE excluded
# These are exactly the options ci.yml's jobs passed before the action
# (docs/notes/ci.md); a change here changes what CI checks.
gz_config() {
  CMAKE_ARGS=()
  case "$1" in
  gcc-off|gcc-on)
    PKGS="cmake build-essential libssl-dev libcurl4-openssl-dev valgrind python3-cryptography"
    COMPILER=gcc; BUILD_TYPE=Release
    if [ "$1" = gcc-on ]; then SANITIZER=asan; s=ON; else SANITIZER=none; s=OFF; fi
    # GZ_INTEROP_PY: gz-net against the independent Python peer (BOLT 8,
    # and BOLT 1 init, ping and pong with factory messages).
    CMAKE_ARGS=(-DGZ_SANITIZE=$s -DGZ_WERROR=ON -DGZ_INTEROP_PY=ON) ;;
  clang-plain|clang-asan)
    PKGS="cmake clang-18 libclang-rt-18-dev libssl-dev"
    COMPILER=clang-18; BUILD_TYPE=Release
    if [ "$1" = clang-asan ]; then SANITIZER=asan; s=ON; else SANITIZER=none; s=OFF; fi
    CMAKE_ARGS=(-DGZ_SANITIZE=$s -DGZW_BREAK_CHECKS=OFF) ;;
  msan)
    PKGS="cmake clang-18 libclang-rt-18-dev"
    COMPILER=clang-18; BUILD_TYPE=RelWithDebInfo; SANITIZER=msan
    # secp256k1's x86-64 assembly is off: MSan cannot see what assembly writes.
    CMAKE_ARGS=(-DGZW_BREAK_CHECKS=OFF
      "-DCMAKE_C_FLAGS=-fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer"
      "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=memory"
      -DSECP256K1_ASM=OFF
      "-DOPENSSL_ROOT_DIR=$HOME/openssl-msan" -DOPENSSL_USE_STATIC_LIBS=TRUE) ;;
  valgrind)
    PKGS="cmake build-essential libssl-dev valgrind"
    COMPILER=gcc; BUILD_TYPE=RelWithDebInfo; SANITIZER=none
    CMAKE_ARGS=(-DGZW_BREAK_CHECKS=OFF) ;;
  debug)
    PKGS="cmake build-essential libssl-dev libcurl4-openssl-dev valgrind"
    COMPILER=gcc; BUILD_TYPE=Debug; SANITIZER=none
    CMAKE_ARGS=(-DGZW_BREAK_CHECKS=OFF) ;;
  fuzz)
    PKGS="cmake clang-18 libclang-rt-18-dev libssl-dev"
    COMPILER=clang-18; BUILD_TYPE=RelWithDebInfo; SANITIZER=fuzz
    CMAKE_ARGS=(-DGZW_BREAK_CHECKS=OFF -DGZ_LIBFUZZER=ON
      "-DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
      "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined") ;;
  interface)
    PKGS="cmake build-essential libssl-dev libcurl4-openssl-dev"
    COMPILER=gcc; BUILD_TYPE=Release; SANITIZER=none
    CMAKE_ARGS=(-DGZ_WERROR=ON -DGZW_BREAK_CHECKS=OFF) ;;
  wallet)
    # wallet-break-checks.yml's build (that workflow keeps its own steps).
    PKGS="cmake build-essential libssl-dev libcurl4-openssl-dev"
    COMPILER=gcc; BUILD_TYPE=Release; SANITIZER=none
    CMAKE_ARGS=(-DGZ_WERROR=ON) ;;
  *)
    echo "::error::unknown build configuration '$1'"; return 1 ;;
  esac
}

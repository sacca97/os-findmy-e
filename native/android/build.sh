#!/bin/sh
# Cross-build libadi_core.so for Android (arm64-v8a and x86_64) into native/android/jniLibs/<abi>/.
#   NDK=/path/to/android-ndk-r27c native/android/build.sh [abi...]
# Needs: rustup targets aarch64-linux-android and x86_64-linux-android, cmake, the NDK (r27 tested).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
NDK=${NDK:?set NDK to the Android NDK directory}
API=${API:-24}
tc=$NDK/toolchains/llvm/prebuilt/linux-x86_64
abis=${*:-"arm64-v8a x86_64"}
for abi in $abis; do
  case $abi in
    arm64-v8a) triple=aarch64-linux-android; rt=aarch64_linux_android; arch=aarch64;;
    x86_64)    triple=x86_64-linux-android;  rt=x86_64_linux_android;  arch=x86_64;;
    *) echo "unknown abi $abi" >&2; exit 1;;
  esac
  # Android has no libpthread (it is part of libc) but libunicorn links -lpthread: give it an empty one.
  stub=$here/build/stub-$abi; mkdir -p "$stub"; : > "$stub/empty.c"
  "$tc/bin/clang" -c "$stub/empty.c" -o "$stub/empty.o" --target=$triple$API
  "$tc/bin/llvm-ar" rc "$stub/libpthread.a" "$stub/empty.o"
  export ANDROID_NDK="$NDK" ANDROID_NDK_HOME="$NDK" ANDROID_NDK_ROOT="$NDK"
  export "CC_$rt=$tc/bin/$triple$API-clang" "CXX_$rt=$tc/bin/$triple$API-clang++" "AR_$rt=$tc/bin/llvm-ar"
  export "CFLAGS_$rt=-L$stub" "CXXFLAGS_$rt=-L$stub"
  # TCG on arm64 calls __clear_cache (icache flush), which rustc leaves out with -nodefaultlibs.
  builtins=$(ls "$tc"/lib/clang/*/lib/linux/libclang_rt.builtins-$arch-android.a | head -1)
  export "CARGO_TARGET_$(echo $rt | tr a-z A-Z)_LINKER=$tc/bin/$triple$API-clang"
  export "CARGO_TARGET_$(echo $rt | tr a-z A-Z)_RUSTFLAGS=-L native=$stub -C link-arg=$builtins"
  export "BINDGEN_EXTRA_CLANG_ARGS_$rt=--sysroot=$tc/sysroot"
  (cd "$here/../adi-core" && cargo build --release --features jni --target "$triple")
  mkdir -p "$here/jniLibs/$abi"
  cp "$here/../adi-core/target/$triple/release/libadi_core.so" "$here/jniLibs/$abi/"
  mkdir -p "$here/build/bin/$abi"; cp "$here/../adi-core/target/$triple/release/adi-cli" "$here/build/bin/$abi/"
  ls -la "$here/jniLibs/$abi/libadi_core.so"
done

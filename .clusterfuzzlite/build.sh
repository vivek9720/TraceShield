#!/bin/bash -eu
ROOT="${SRC:-$(pwd)}"
cd "$ROOT"
COMMON_SRC=$(find src -name '*.cpp' | sort)
mkdir -p "$OUT"
for target in packet_fuzzer ioc_fuzzer rules_fuzzer policy_fuzzer; do
  $CXX $CXXFLAGS -std=c++17 -Iinclude $COMMON_SRC "fuzz/${target}.cc" $LIB_FUZZING_ENGINE -o "$OUT/${target}"
done

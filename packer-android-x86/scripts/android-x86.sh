#!/bin/sh
cmake ..                                \
  -DANDROID_ABI="x86"                   \
  -DANDROID_PLATFORM=android-24         \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo     \
  -DCMAKE_TOOLCHAIN_FILE=${ANDROID_SDK}/ndk-bundle/build/cmake/android.toolchain.cmake

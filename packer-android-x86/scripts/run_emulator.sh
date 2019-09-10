#!/usr/bin/env bash

${ANDROID_HOME}/emulator/emulator \
  -camera-back none \
  -camera-front none \
  -selinux permissive \
  -screen no-touch \
  -accel on \
  -no-boot-anim \
  -noaudio \
  -no-window \
  -shell \
  @android-27-x86_64 -logcat i

# QBDI Packer Example

This directory contains the materials associated with the blog post [QBDI 0.7.0](https://blog.quarkslab.com/qbdi-070.html)

## Quick Start

```bash
  $ mdkir build
  $ sh ../../scripts/android-x86.sh
  $ make libshellx_qbdi
  # Run the an x86/x86-64 emulator
  $ make push
```

Then, you can run ``libshellx_qbdi`` and observe this kind of output

```bash
$ adb shell /data/local/tmp/libshellx_qbdi
  Call external method mprotect(0xf3567000, 8192, PROT_READ | PROT_WRITE)
  Call external method mprotect(0xf3567000, 8192, PROT_READ | PROT_EXEC)
  Call external method getenv("DEX_PATH")
  Call external method __android_log_print
```

Once finished, you can notice ``out.so`` that handles the unpacked library.

```bash
$ adb shell ls /data/local/tmp
  libQBDI.so
  libshellx-3.0.0.0_WITHOUT_CTOR.so
  libshellx_qbdi
  out.so
```

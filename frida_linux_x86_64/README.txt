A short usage of QBDI with frida on Linux X86-64

To use it, build the QBDI package (or download a release of QBDI >0.9.0)::

    git clone https://github.com/QBDI/QBDI.git
    mkdir -p QBDI/build
    cd QBDI/build
    cmake .. -DQBDI_PLATFORM=linux -DQBDI_ARCH=X86_64
    cmake --build . 
    cpack
    ls -l QBDI-*-linux-X86_64.tar.gz

    cd ../..

    git clone https://github.com/QBDI/examples.git
    ./examples/frida_linux_x86_64/run.sh QBDI/build/QBDI-*-linux-X86_64.tar.gz build



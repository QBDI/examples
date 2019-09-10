#include <iostream>

#include <dlfcn.h>
#include <sys/mman.h>

#include <QBDI.h>
#include <LIEF/LIEF.hpp>

using namespace QBDI;

struct context_t {
    LIEF::ELF::Binary* lib_lief;
    Range<rword>& patch_range;
    rword base_addr;
    std::map<rword, std::string> symbol_resolution;
};

VMAction onExecBroker(VMInstanceRef vm, const VMState *vmState, GPRState *gprState, FPRState *fprState, void *raw_data) {
    auto ctx = reinterpret_cast<context_t*>(raw_data);

    // Check that the event is a CALL
    if ((vmState->event & EXEC_TRANSFER_CALL) == 0) {
        return CONTINUE;
    }

    std::string function;
    bool name_found = false;

    auto it = ctx->symbol_resolution.find(gprState->eip);
    if (it != std::end(ctx->symbol_resolution)) {
        function = it->second;
        name_found = true;
    } else {
        // find library with full path
        for (MemoryMap& map : getCurrentProcessMaps(true)) {
            if ((map.permission & PF_EXEC) && map.range.contains(gprState->eip)) {
                std::unique_ptr<LIEF::ELF::Binary> externlib = LIEF::ELF::Parser::parse(map.name);

                for (LIEF::ELF::Symbol& sym : externlib->exported_symbols()) {
                    if (gprState->eip - map.range.start == sym.value()) {
                        function = sym.demangled_name();
                        ctx->symbol_resolution[gprState->eip] = function;
                        name_found = true;
                        break;
                    }
                }
                break;
            }
        }
    }

    if (not name_found) {
        printf("Cannot resolve the address %p\n", (void*) gprState->eip);
        return CONTINUE;
    }

    if (function == "mprotect") {
        int prot = *reinterpret_cast<rword*>(gprState->esp + 3*sizeof(void*));
        std::string prot_char;
        if (prot == PROT_NONE) prot_char += "PROT_NONE";
        if (prot & PROT_READ) prot_char += "PROT_READ | ";
        if (prot & PROT_WRITE) prot_char += "PROT_WRITE | ";
        if (prot & PROT_EXEC) prot_char += "PROT_EXEC";
        if (prot_char.size() > 3 && prot_char[prot_char.size() - 2] == '|') prot_char.erase(prot_char.size() - 3, 3);
        printf("Call external method %s(0x%x, %d, %s)\n",
                function.c_str(),
                *reinterpret_cast<rword*>(gprState->esp + 1*sizeof(void*)),
                *reinterpret_cast<rword*>(gprState->esp + 2*sizeof(void*)),
                prot_char.c_str());

      return CONTINUE;
    }

    if (function == "getenv") {
        printf("Call external method %s(\"%s\")\n",
                function.c_str(),
                *reinterpret_cast<char**>(gprState->esp + 1 * sizeof(void*))
                );

      return CONTINUE;
    }

    printf("Call external method %s\n", function.c_str());
    return CONTINUE;
}

VMAction onWrite(VMInstanceRef vm, GPRState *gprState, FPRState *fprState, void *raw_data) {
    auto ctx = reinterpret_cast<context_t*>(raw_data);
    std::vector<MemoryAccess> mem_access = vm->getInstMemoryAccess();

    for (MemoryAccess& access: mem_access) {

        if ((access.type & MEMORY_WRITE) != 0 && ctx->patch_range.contains(access.accessAddress)) {
            // Patch the library with LIEF using memory acess information from QBDI
            ctx->lib_lief->patch_address(
                // Relative address
                access.accessAddress - ctx->base_addr,
                // Value being written
                access.value,
                // Size of the value being written
                access.size
            );
        }
    }

    return CONTINUE;
}

int main(int argc, char** argv) {

    const char *lib_path;

    if (argc >= 2) {
        lib_path = argv[1];
    } else {
        lib_path = "/data/local/tmp/libshellx-3.0.0.0_WITHOUT_CTOR.so";
    }
    std::unique_ptr<LIEF::ELF::Binary> lib_lief = LIEF::ELF::Parser::parse(lib_path);
    void* handle = dlopen(lib_path, RTLD_LAZY | RTLD_LOCAL);

    if (handle == nullptr or lib_lief.get() == nullptr) {
        perror("Cannot load library");
        exit(EXIT_FAILURE);
    }

    const char* lib_name = lib_path;
    if (strrchr(lib_name, '/') != nullptr)
        lib_name = strrchr(lib_name, '/') + 1;

    rword base_addr = 0;
    Range<rword> libshellx_code_range(0, 0);

    // Find Library base address
    for (MemoryMap& map : getCurrentProcessMaps()) {
        if ((map.permission & PF_EXEC) && map.name == lib_name /* libshellx-3.0.0.0_WITHOUT_CONSTR.so */) {
            libshellx_code_range = map.range;
            base_addr = map.range.start;
        }
    }

    // Better to use the API from QBDI about the current memory layout
    /*
     *   for (LIEF::ELF::Symbol& sym: lib_lief.get()->exported_symbols()) {
     *       base_addr = reinterpret_cast<rword>(dlsym(handle, sym.name().c_str()));
     *       if (base_addr == 0) continue;
     *       base_addr -= sym.value();
     *       break;
     *   }
     */

    if (base_addr == 0) {
        std::cerr << "Fail to find base address" << std::endl;
        return -1;
    }

    rword ctr_addr = base_addr + /* CTOR Addr */ 0x931;

    // Init QBDI
    VM vm;
    uint8_t *fakestack = nullptr;

    // Allocate a stack for QBDI
    GPRState *state = vm.getGPRState();
    allocateVirtualStack(state, 1 << 20, &fakestack);

    // patch the library when a data is write on the code section
    context_t context = {
      lib_lief.get(),       // LIEF Handler
      libshellx_code_range, // .text code range
      base_addr             // Library base address
    };

    // Add callback on Memory write
    vm.addMemRangeCB(
        libshellx_code_range.start, libshellx_code_range.end,
        MEMORY_WRITE,
        onWrite,
        &context
    );

    // Listen to "CALL" event
    vm.addVMEventCB(EXEC_TRANSFER_CALL, onExecBroker, &context);

    // Only instrument the libshellx library
    vm.addInstrumentedModuleFromAddr(base_addr);

    // Call the construction in QBDI
    rword ret;
    vm.call(&ret, ctr_addr, /* args: none */{});

    // Save the patched library
    lib_lief->write("out.so");

    return 0;
}


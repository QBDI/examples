// QBDI
import { VM, InstPosition, MemoryAccessType, AnalysisType, VMEvent, VMAction, InstrRuleDataCBK } from "./frida-qbdi.js";

// Initialize QBDI
var vm = new VM();
vm.setLogPriority(1);
var state = vm.getGPRState();
var stack = vm.allocateVirtualStack(state, 0x100000);

// Instrument "Secret" function from demo.bin
var funcPtr = Module.findExportByName(null, "Secret");
if (!funcPtr) {
    funcPtr = DebugSymbol.fromName("Secret").address;
}
console.log(funcPtr);
vm.addInstrumentedModuleFromAddr(funcPtr);

// Callback on every instruction
// This callback will print context and display current instruction address and dissassembly
// We choose to print only XOR instructions
var icbk = vm.newInstCallback(function(vm, gpr, fpr, data) {
    var inst = vm.getInstAnalysis(AnalysisType.ANALYSIS_INSTRUCTION | AnalysisType.ANALYSIS_DISASSEMBLY | AnalysisType.ANALYSIS_OPERANDS);
    gpr.dump(true); // Display context
    console.log(data + "0x" + inst.address.toString(16) + " " + inst.disassembly); // Display instruction dissassembly
    console.log(data + "nbop: " + inst.operands.length);
    for (var i = 0; i < inst.operands.length; i++) {
        console.log(data + "    [" + i + "] type:" + inst.operands[i].type
          + " flag:" + inst.operands[i].flag
          + " value:" + inst.operands[i].value
          + " size:" + inst.operands[i].size
          + " regOff:" + inst.operands[i].regOff
          + " regCtxIdx:" + inst.operands[i].regCtxIdx
          + " regName:" + inst.operands[i].regName
          + " regAccess:" + inst.operands[i].regAccess);
    }
    return VMAction.CONTINUE;
});
var iid = vm.addCodeCB(InstPosition.PREINST, icbk, "==> ");

var vcbk = vm.newInstCallback(function(vm, gpr, fpr, data) {
    // Retrieve the related memory accesses.
    const memAccesses = vm.getInstMemoryAccess();

    // Iterate over memory accesses (may be more than one).
    memAccesses.forEach(function (access) {
        // Determine the type of access
        const type = (access.type == MemoryAccessType.MEMORY_READ) ? "Read" : "Write";
        console.log(data + type + " " + ptr(access.value) + " at " + ptr(access.accessAddress) + " [size: " + ptr(access.size) + "]");
    });
    return VMAction.CONTINUE;
});
vm.addMemAccessCB(MemoryAccessType.MEMORY_READ_WRITE, vcbk, "[+] ");

var vmcb = vm.newVMCallback(function(vm, state, gpr, fpr, data) {
    console.log(data + "End sequence " + state.sequenceEnd.toString(16));
    return VMAction.CONTINUE;
});
vm.addVMEventCB(VMEvent.SEQUENCE_EXIT, vmcb, "[-] ");

var printCB = vm.newInstCallback(function(vm, gpr, fpr, data) {
    console.log(data);
    return VMAction.CONTINUE;
});
var instrRuleCB = vm.newInstrRuleCallback(function(vm, ana, data) {
    console.log(data + "Instrument 0x" + ana.address.toString(16) + " " + ana.disassembly);
    return [new InstrRuleDataCBK(InstPosition.POSTINST, printCB, "==[*] " + ana.disassembly)];
});
vm.addInstrRule(instrRuleCB, AnalysisType.ANALYSIS_INSTRUCTION | AnalysisType.ANALYSIS_DISASSEMBLY | AnalysisType.ANALYSIS_OPERANDS, "[*] ");

var vmcbk = vm.newVMCallback(function(vm, state, gpr, fpr, data) {
    var msg = "start:0x" + state.basicBlockStart.toString(16) + ", end:0x" + state.basicBlockEnd.toString(16);
    if (state.event & VMEvent.BASIC_BLOCK_NEW) {
        msg = msg + " BASIC_BLOCK_NEW";
    }
    if (state.event & VMEvent.BASIC_BLOCK_ENTRY) {
        msg = msg + " BASIC_BLOCK_ENTRY";
    }
    if (state.event & VMEvent.BASIC_BLOCK_EXIT) {
        msg = msg + " BASIC_BLOCK_EXIT";
    }
    console.log(msg);
    return VMAction.CONTINUE;
});
vm.addVMEventCB(VMEvent.BASIC_BLOCK_NEW | VMEvent.BASIC_BLOCK_ENTRY | VMEvent.BASIC_BLOCK_EXIT, vmcbk, null);

var covcbk = vm.newVMCallback(function(vm, state, gpr, fpr, cov) {
    if ( (! cov[state.basicBlockEnd]) || state.basicBlockStart < cov[state.basicBlockEnd][0] ) {
        cov[state.basicBlockEnd] = [state.basicBlockStart, state.basicBlockEnd]
    }
    return VMAction.CONTINUE;
});
var cov = {};

vm.addVMEventCB(VMEvent.BASIC_BLOCK_NEW, covcbk, cov);

// Allocate a string in remote process memory
var strP = Memory.allocUtf8String("Hello world !");
// Call the Secret function using QBDI and with our string as argument
vm.call(funcPtr, [strP]);

for(var c in cov){
    console.log("0x" + cov[c][0].toString(16) + " to 0x" + cov[c][1].toString(16));
}

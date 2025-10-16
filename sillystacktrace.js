const TARGET_RVAS = [
    0xcc16550
];

const CONFIG = {
    maxStackDepth: 10,     
    showArguments: true,    
    detectArgCount: true,
    showCallCount: true,
    showReturnValue: true,
};

const mainModule = Process.enumerateModules()[0];
const stats = {
    callCounts: new Map(),
    totalCalls: 0
};

console.log(`[*] Target: ${mainModule.name}`);
console.log(`[*] Base: ${mainModule.base}`);
console.log(`[*] Hooking ${TARGET_RVAS.length} RVAs...\n`);

function formatAddress(address) {
    const rva = address.sub(mainModule.base);
    return `${mainModule.name}+0x${rva.toString(16)}`;
}

function getStackTrace(context, maxDepth = CONFIG.maxStackDepth) {
    const trace = [];

    try {
        const backtrace = Thread.backtrace(context, Backtracer.ACCURATE);

        for (let i = 1; i < Math.min(backtrace.length, maxDepth + 1); i++) {
            const addr = backtrace[i];
            const module = Process.findModuleByAddress(addr);

            if (module) {
                trace.push({
                    address: addr,
                    formatted: formatAddress(addr),
                    module: module.name
                });
            }
        }
    } catch (e) {
        console.log(`[-] Error getting stacktrace: ${e}`);
    }

    return trace;
}

function detectArgumentCount(address) {
    if (!CONFIG.detectArgCount) return 0;

    const usedRegs = new Set();
    const stackAccesses = new Set();

    try {
        let addr = address;
        let instructionCount = 0;
        let reachedMainCode = false;
        for (let i = 0; i < 50 && instructionCount < 30; i++) {
            const instr = Instruction.parse(addr);
            const disasm = instr.toString().toLowerCase();

            if (disasm.includes('push') ||
                disasm.includes('sub rsp') ||
                disasm.includes('movaps') ||
                disasm.includes('movups')) {
                addr = addr.add(instr.size);
                continue;
            }

            if (disasm.includes('mov') && !disasm.includes('movaps') && !disasm.includes('movups')) {
                const savePattern = /mov\s+([a-z0-9]+),\s+(rcx|rdx|r8|r9)/;
                const match = disasm.match(savePattern);

                if (match) {
                    const sourceReg = match[2];
                    if (sourceReg === 'rcx') usedRegs.add(1);
                    else if (sourceReg === 'rdx') usedRegs.add(2);
                    else if (sourceReg === 'r8') usedRegs.add(3);
                    else if (sourceReg === 'r9') usedRegs.add(4);
                    reachedMainCode = true;
                }

                if (disasm.includes(', rcx') || disasm.includes('[rcx')) usedRegs.add(1);
                if (disasm.includes(', rdx') || disasm.includes('[rdx')) usedRegs.add(2);
                if (disasm.includes(', r8') || disasm.includes('[r8')) usedRegs.add(3);
                if (disasm.includes(', r9') || disasm.includes('[r9')) usedRegs.add(4);
            }

            const stackMatch = disasm.match(/\[rsp\s*\+\s*0x([0-9a-f]+)\]/);
            if (stackMatch && reachedMainCode) {
                const offset = parseInt(stackMatch[1], 16);
                if (offset >= 0x28 && offset < 0x80) {
                    const argNum = Math.floor((offset - 0x28) / 8) + 5;
                    if (argNum <= 10) stackAccesses.add(argNum);
                }
            }

            // mb cmp     cs:byte_xxxxxxxx, 0 
            if (disasm.includes('call') || disasm.includes('jmp') || disasm.includes('ret')) {
                break;
            }

            addr = addr.add(instr.size);
            instructionCount++;
        }
    } catch (e) {
   
    }

    let maxArg = 0;
    usedRegs.forEach(num => maxArg = Math.max(maxArg, num));
    stackAccesses.forEach(num => maxArg = Math.max(maxArg, num));

    return maxArg;
}

function printStackTrace(functionName, callCount, argCount, stackTrace) {
    const countStr = CONFIG.showCallCount ? `[${callCount.toString().padStart(3)}] ` : '';
    const argStr = CONFIG.showArguments && argCount > 0 ? ` (${argCount} args)` : '';

    console.log(`${countStr}${functionName}${argStr} called`);

    stackTrace.forEach((frame, index) => {
        const indent = '  '.repeat(index);
        console.log(`${indent}↳ ${frame.formatted}`);
    });
}

TARGET_RVAS.forEach(rva => {
    try {
        const address = mainModule.base.add(rva);
        const functionName = `func_${rva.toString(16)}`;
        const argCount = detectArgumentCount(address);

        //console.log(`[+] Hooking ${functionName} at RVA:0x${rva.toString(16)} (${argCount} args detected)`);

        //console.log('[*] First instructions:');
        //let addr = address;
        //for (let i = 0; i < 10; i++) {
        //    try {
        //        const instr = Instruction.parse(addr);
        //        console.log(`    ${addr}: ${instr}`);
        //        addr = addr.add(instr.size);
        //    } catch (e) {
        //        break;
        //    }
        //}
        //console.log('');

        Interceptor.attach(address, {
            onEnter: function (args) {
                stats.totalCalls++;

                const key = rva.toString();
                const currentCount = stats.callCounts.get(key) || 0;
                const newCount = currentCount + 1;
                stats.callCounts.set(key, newCount);

                const stackTrace = getStackTrace(this.context);

                printStackTrace(functionName, newCount, argCount, stackTrace);

                if (CONFIG.showArguments && argCount > 0) {
                    console.log('Arguments:');
                    const argNames = ['rcx', 'rdx', 'r8', 'r9'];
                    for (let i = 0; i < Math.min(argCount, 4); i++) {
                        try {
                            const value = args[i];
                            console.log(`  arg${i} (${argNames[i]}): 0x${value.toString(16)}`);

                            //try {
                            //    if (value && !value.isNull()) {
                            //        const pointed = value.readU64();
                            //        if (pointed) {
                            //            console.log(`    └─> points to: 0x${pointed.toString(16)}`);
                            //        }
                            //    }
                            //} catch (e) { }
                        } catch (e) {
                            console.log(`  arg${i}: <error reading>`);
                        }
                    }

                    if (argCount > 4) {
                        console.log('  Stack arguments:');
                        for (let i = 4; i < argCount; i++) {
                            try {
                                const offset = 0x28 + (i - 4) * 8;
                                const value = this.context.rsp.add(offset).readU64();
                                console.log(`    arg${i} [rsp+0x${offset.toString(16)}]: 0x${value.toString(16)}`);
                            } catch (e) {
                                console.log(`    arg${i}: <error reading>`);
                            }
                        }
                    }
                    console.log('');
                }
            },

            onLeave: function (retval) {
                if (CONFIG.showReturnValue) {
                    console.log(`  └─> Returns: ${retval}\n`);
                }
            }
        });

    } catch (e) {
        console.log(`[-] Failed to hook RVA 0x${rva.toString(16)}: ${e}`);
    }
});

console.log(`[*] Successfully hooked ${TARGET_RVAS.length} functions`);
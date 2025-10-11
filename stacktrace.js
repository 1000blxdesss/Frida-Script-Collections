const CONFIG = {
    showDetails: true,
    filterByModule: true, // remove export/import funcs
    maxHooksWTF: 5000,
    excludePatterns: [
        '__security_check_cookie',
        '__GSHandlerCheck',
        'memset',
        'memcpy',
        'RtlCaptureContext'
    ],
    allowedModules: [
        //'detectstacktracetest.exe',
        'kernel32.dll',
        'user32.dll'
    ],
};

function filter(moduleName) {
    if (!CONFIG.filterByModule) {
        return true;
    }

    // mainmodule
    if (moduleName === mainModule.name) {
        return true;
    }

    // garbage
    if (CONFIG.allowedModules.some(allowed =>
        moduleName.toLowerCase().includes(allowed.toLowerCase())
    )) {
        return true;
    }

    return false;
}

function getThreadName(threadId) {
    return `TID:${threadId}`;
}

// pars PE -> get Exception Directory (RUNTIME_FUNCTION table)
function findAllFunctions(moduleBase, moduleSize) {
    const functions = [];
    let foundCount = 0;

    try {
        const dosHeader = moduleBase;
        const e_lfanew = moduleBase.add(0x3C).readU32();
        const ntHeader = moduleBase.add(e_lfanew);

        if (ntHeader.readU32() !== 0x00004550) {
            console.log("[-] Invalid PE sig, bro a u idiot?");
            return functions;
        }
        // skip File Header -> get Optional Header
        const optionalHeader = ntHeader.add(24);
        const magic = optionalHeader.readU16();

        if (magic !== 0x020B) {
            console.log("[-] Not a PE32+ file");
            return functions;
        }
        // Exception Directory (0x8C) in Optional Header (x64)
        // Data Directories start offset 112 (0x70)
        // Exception Directory -  directory (index 3), offset = 0x70 + 3*8 = 0x88
        const exceptionDirOffset = 0x88;
        const exceptionDirRVA = optionalHeader.add(exceptionDirOffset).readU32();
        const exceptionDirSize = optionalHeader.add(exceptionDirOffset + 4).readU32();

        //console.log(`[+] Exception Directory: RVA=0x${exceptionDirRVA.toString(16)}, Size=0x${exceptionDirSize.toString(16)}`);

        if (exceptionDirRVA === 0 || exceptionDirSize === 0) {
            console.log("[-] No Exception Directory found :(");
            return functions;
        }
        // RUNTIME_FUNCTION
        // each structure = 12 bytes (BeginAddress, EndAddress, UnwindData)
        const exceptionTableAddr = moduleBase.add(exceptionDirRVA);
        const numEntries = Math.floor(exceptionDirSize / 12);

        console.log(`[+] Found ${numEntries} RUNTIME_FUNCTION entries\n`);

        for (let i = 0; i < numEntries && i < CONFIG.maxHooksWTF; i++) {
            try {
                const entry = exceptionTableAddr.add(i * 12);
                const beginRVA = entry.readU32();
                const endRVA = entry.add(4).readU32();
                const unwindDataRVA = entry.add(8).readU32();


                if (beginRVA === 0 && endRVA === 0) {
                    break;
                }

                if (beginRVA > 0 && beginRVA < moduleSize && endRVA > beginRVA) {
                    foundCount++;

                    const funcAddress = moduleBase.add(beginRVA);
                    const symbol = DebugSymbol.fromAddress(funcAddress);

                    functions.push({
                        rva: beginRVA,
                        address: funcAddress,
                        endRva: endRVA,
                        size: endRVA - beginRVA,
                        symbol: symbol
                    });

                    //console.log(`[${foundCount.toString().padStart(2)}] RVA:0x${beginRVA.toString(16).padStart(4, '0')} | ` +
                    //    `Size:${(endRVA - beginRVA).toString().padStart(3)} bytes | ` +
                    //    `Address:${funcAddress} | ` +
                    //    `Symbol: ${symbol}`);
                }
            } catch (e) {
                console.log(`[-] Failed to read entry ${i}: ${e}`);
            }
        }

    } catch (e) {
        console.log(`[-] Error parsing PE: ${e.message}`);
    }

    return functions;
}

function shouldExclude(address) {
    try {
        const symbol = DebugSymbol.fromAddress(address);
        if (symbol && symbol.name) {
            for (const pattern of CONFIG.excludePatterns) {
                if (symbol.name.includes(pattern)) {
                    return true;
                }
            }
        }
    } catch (e) { }
    return false;
}

const mainModule = Process.enumerateModules()[0];
console.log(`[*] Target module: ${mainModule.name}`);
console.log(`[*] Base: ${mainModule.base}`);
console.log(`[*] Size: 0x${mainModule.size.toString(16)}\n`); // idk for some tests

const functions = findAllFunctions(mainModule.base, mainModule.size);

if (functions.length === 0) {
    console.log("\n[-] xd 0 funcs in RUNTIME_FUNCTION");

    const patterns = [
        "48 83 EC",        // sub rsp, XX
        "48 81 EC"         // sub rsp, XXXXXXXX
    ];

    const found = new Set();
    patterns.forEach(pattern => {
        try {
            const matches = Memory.scanSync(mainModule.base, mainModule.size, pattern);
            matches.forEach(match => {
                const rva = match.address.sub(mainModule.base).toInt32();
                if (!found.has(rva)) {
                    found.add(rva);
                    functions.push({
                        rva: rva,
                        address: match.address,
                        symbol: DebugSymbol.fromAddress(match.address) //
                    });
                }
            });
        } catch (e) { }
    });

    console.log(`[+] Pattern scan found ${functions.length} funcs`);
}



let hookedCount = 0;
const hooked = new Set();

functions.forEach((func, idx) => {
    try {
        const addrStr = func.address.toString();
        if (hooked.has(addrStr)) return;
        if (shouldExclude(func.address)) return;

        const rva = `0x${func.rva.toString(16)}`;
        const va = func.address.toString();

        let funcName = func.symbol || 'unknown';
        if (funcName === 'unknown') {
            try {
                const symbol = DebugSymbol.fromAddress(func.address);
                if (symbol && symbol.name) {
                    funcName = symbol.name;
                }
            } catch (e) { }
        }

        Interceptor.attach(func.address, {
            onEnter: function (args) {
                const threadId = Process.getCurrentThreadId();
                const threadName = getThreadName(threadId);

                const fromModule = Process.findModuleByAddress(this.returnAddress);
                const fromModuleName = fromModule ? fromModule.name : 'unknown';


                if (!filter(fromModuleName)) {
                    return;
                }
                //if (CONFIG.filterByModule && fromModuleName !== mainModule.name) {
                //    return;
                //}

                let output = `${funcName} RVA:${rva} VA:${va} From:${fromModuleName} ${threadName}`;
                console.log(output);
            },
            onLeave: function (retval) {
                const fromModule = Process.findModuleByAddress(this.returnAddress);
                const fromModuleName = fromModule ? fromModule.name : 'unknown';

                if (filter(fromModuleName)) {
                    console.log(`  Return: ${retval}`);
                }
            }
        });

        hooked.add(addrStr);
        hookedCount++;

    } catch (e) {
        console.log(`[-] Failed at func ${func.address}: ${e}`);
    }
});

console.log("=".repeat(80));
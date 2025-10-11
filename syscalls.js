console.log("[+] Architecture: " + Process.arch);

const SYSCALL_READV = 310;
const SYSCALL_WRITEV = 311;

const syscallAddr = Module.findExportByName("libc.so", "syscall");
console.log("[+] syscall function found at: " + syscallAddr);

Interceptor.attach(syscallAddr, {
    onEnter: function (args) {
            const syscallNum = args[0].toInt32();

            if (syscallNum === SYSCALL_READV || syscallNum === SYSCALL_WRITEV) {
                console.log(`\n${'='.repeat(60)}`);
                console.log(`[!] ?!?!?!?!?!?!?: ${syscallNum} (${syscallNum === SYSCALL_READV ? 'READV' : 'WRITEV'})`);
                console.log(`${'='.repeat(60)}`);

                this.syscallNum = syscallNum;
                this.target_pid = args[1].toInt32();
                this.size = args[4].toInt32();
                this.detected = true; // vroo wat

                this.callerReturnAddr = this.returnAddress;
                //console.log(`    Calling PID: ${Process.id}`);
                //console.log(`    Target PID: ${this.target_pid}`);
                //console.log(`    Size: ${this.size} bytes`);
            }
        },

    onLeave: function (retval) {
            if (!this.detected) return;

            console.log(`    Return value: ${retval.toInt32()}`);

            if (this.callerReturnAddr) {
                console.log(`\n  [1] Return Address (this.returnAddress):`);
                console.log(`      Address: ${this.callerReturnAddr}`);

                const module1 = Process.findModuleByAddress(this.callerReturnAddr);
                if (module1) {
                    const offset1 = this.callerReturnAddr.sub(module1.base);
                    console.log(`      Module: ${module1.name}`);
                    console.log(`      Base: ${module1.base}`);
                    console.log(`      Offset: 0x${offset1.toString(16)}`);
                    console.log(`      Path: ${module1.path}`);
                }

                const symbol1 = DebugSymbol.fromAddress(this.callerReturnAddr);
                if (symbol1) {
                    console.log(`      Symbol: ${symbol1}`);
                }
            }
        }
});


console.log("[+] Hooks installed. Waiting for magic...");
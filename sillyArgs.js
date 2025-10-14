const mainModule = Process.enumerateModules()[0];
function detectAllArgs(startAddr) {

    const foundArgs = [];
    let currentAddr = startAddr;

    for (let i = 0; i < 20; i++) {
        try {
            const instr = Instruction.parse(currentAddr);
            const disasm = instr.toString();

            // MOV (reg)
            if ((instr.mnemonic === 'mov' || instr.mnemonic === 'movzx')) {
                // reg args
                if (disasm.includes(' r9') && !foundArgs.some(a => a.source === 'R9')) {
                    foundArgs.push({ type: 'arg3', source: 'R9', instruction: disasm });
                }
                else if (disasm.includes(' r8') && !foundArgs.some(a => a.source === 'R8')) {
                    foundArgs.push({ type: 'arg2', source: 'R8', instruction: disasm });
                }
                else if (disasm.includes(' rdx') && !foundArgs.some(a => a.source === 'RDX')) {
                    foundArgs.push({ type: 'arg1', source: 'RDX', instruction: disasm });
                }
                else if (disasm.includes(' rcx') && !foundArgs.some(a => a.source === 'RCX')) {
                    foundArgs.push({ type: 'this', source: 'RCX', instruction: disasm });
                }
                // MOV (stack) - [rsp + XXX]
                else if (disasm.includes('[rsp + 0x')) {
                    const stackMatch = disasm.match(/\[rsp \+ (0x[0-9A-F]+)\]/);
                    if (stackMatch) {
                        const offset = stackMatch[1];
                        foundArgs.push({
                            type: `arg${foundArgs.length}`,
                            source: `stack[${offset}]`,
                            instruction: disasm
                        });
                    }
                }
                else if (disasm.includes('[rsp+0x')) {
                    const stackMatch = disasm.match(/\[rsp\+0x([0-9A-F]+)\]/);
                    if (stackMatch) {
                        const offset = stackMatch[1];
                        foundArgs.push({
                            type: `arg${foundArgs.length}`,
                            source: `stack[${offset}h]`,
                            instruction: disasm
                        });
                    }
                }
            }

            currentAddr = currentAddr.add(instr.size);

        } catch (e) {
            break;
        }
    }

    foundArgs.forEach(arg => {
        console.log(`   ${arg.type.padEnd(8)} ${arg.source.padEnd(15)} ${arg.instruction}`);
    });

    return foundArgs;
}


const targetAddr = mainModule.base.add(0xae91d20);
const args = detectAllArgs(targetAddr);


console.log(`JLDLLCJJMLE(${args.map(a => a.type === 'this' ? 'this' : a.type).join(', ')})`);
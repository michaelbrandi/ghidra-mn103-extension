import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

// Linear-sweep dump: for each address, emit "addr|hexbytes|mnemonic operands"
// so it can be diffed against objdump for the identical byte stream.
public class MN103DumpDisasm extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        long start = (a.length>0 && !a[0].isEmpty()) ? Long.decode(a[0]) : 0;
        long end   = (a.length>1 && !a[1].isEmpty()) ? Long.decode(a[1]) : -1;
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address cur = toAddr(start);
        Address stop = (end>=0)? toAddr(end) : blk.getEnd();
        while (cur != null && cur.compareTo(stop) <= 0) {
            disassemble(cur);
            Instruction ins = getInstructionAt(cur);
            if (ins == null) { cur = cur.next(); continue; }
            byte[] b = ins.getBytes();
            StringBuilder hx = new StringBuilder();
            for (byte x : b) hx.append(String.format("%02x", x & 0xff));
            println(String.format("D|%08x|%s|%s", cur.getOffset(), hx.toString(), ins.toString()));
            cur = cur.add(ins.getLength());
        }
    }
}

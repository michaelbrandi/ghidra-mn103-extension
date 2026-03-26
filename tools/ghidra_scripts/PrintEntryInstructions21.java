import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;

public class PrintEntryInstructions21 extends GhidraScript {
    private static long parseAddrArg(String s) {
        String v = s.trim().toLowerCase();
        if (v.startsWith("0x")) {
            return Long.parseUnsignedLong(v.substring(2), 16);
        }
        return Long.parseLong(v, 10);
    }

    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x2000);
        Symbol entrySym = getSymbol("entry", null);
        if (entrySym != null) {
            entry = entrySym.getAddress();
        }
        String[] args = getScriptArgs();
        if (args != null && args.length > 0) {
            entry = toAddr(parseAddrArg(args[0]));
        }

        println("Program: " + currentProgram.getName());
        println("Entry: " + entry);

        disassemble(entry);

        Listing listing = currentProgram.getListing();
        Instruction inst = listing.getInstructionAt(entry);
        int count = 0;
        int maxCount = 80;
        while (inst != null && count < maxCount) {
            println(inst.getAddress() + ": " + inst);
            inst = inst.getNext();
            count++;
        }

        println("Printed " + count + " instructions");
    }
}

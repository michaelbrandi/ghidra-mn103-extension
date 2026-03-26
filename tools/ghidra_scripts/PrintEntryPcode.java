import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class PrintEntryPcode extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address start = currentProgram.getMinAddress();
        int maxCount = 12;

        String[] args = getScriptArgs();
        if (args.length >= 1 && !args[0].isEmpty()) {
            start = toAddr(args[0]);
        } else if (currentProgram.getListing().getNumInstructions() > 0) {
            Address ep = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
                ? currentProgram.getSymbolTable().getExternalEntryPointIterator().next()
                : null;
            if (ep != null) {
                start = ep;
            }
        }
        if (args.length >= 2 && !args[1].isEmpty()) {
            maxCount = Integer.parseInt(args[1]);
        }

        println("Program: " + currentProgram.getName());
        println("Start:   " + start);

        Instruction insn = currentProgram.getListing().getInstructionAt(start);
        if (insn == null) {
            disassemble(start);
            insn = currentProgram.getListing().getInstructionAt(start);
        }
        int printed = 0;
        while (insn != null && printed < maxCount) {
            println(String.format("%s: %s  [flow=%s]", insn.getAddress(), insn, insn.getFlowType()));
            PcodeOp[] pcode = insn.getPcode();
            for (PcodeOp op : pcode) {
                println("  " + op);
            }
            insn = insn.getNext();
            printed++;
        }
        println("Printed " + printed + " instruction(s).");
    }
}

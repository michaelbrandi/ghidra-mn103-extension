import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileAt21 extends GhidraScript {
    private static long parseAddrArg(String s) {
        String v = s.trim().toLowerCase();
        if (v.startsWith("0x")) {
            return Long.parseUnsignedLong(v.substring(2), 16);
        }
        return Long.parseLong(v, 10);
    }

    @Override
    public void run() throws Exception {
        Address target = toAddr(0x2000);
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isBlank()) {
            target = toAddr(parseAddrArg(args[0]));
        }

        Function f = getFunctionContaining(target);
        if (f == null) {
            disassemble(target);
            createFunction(target, null);
            f = getFunctionContaining(target);
        }

        if (f == null) {
            println("No function found at " + target);
            return;
        }

        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) {
            println("Failed to open program in decompiler");
            return;
        }

        DecompileResults res = ifc.decompileFunction(f, 60, monitor);
        println("Function: " + f.getName() + " @ " + f.getEntryPoint());
        println("Completed: " + res.decompileCompleted());
        println("TimedOut: " + res.isTimedOut());
        String err = res.getErrorMessage();
        println("Error: " + (err == null ? "" : err));

        if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
            println("--- Decompiled C ---");
            println(res.getDecompiledFunction().getC());
        }
    }
}

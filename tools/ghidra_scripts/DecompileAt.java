import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address target = currentAddress;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            target = toAddr(args[0]);
        } else if (target == null) {
            target = currentProgram.getMinAddress();
        }

        Function fn = currentProgram.getFunctionManager().getFunctionContaining(target);
        if (fn == null) {
            disassemble(target);
            createFunction(target, null);
            fn = currentProgram.getFunctionManager().getFunctionContaining(target);
        }
        if (fn == null) {
            println("No function at " + target);
            return;
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        DecompileResults res = ifc.decompileFunction(fn, 30, monitor);

        println("Function: " + fn.getName() + " @ " + fn.getEntryPoint());
        println("Completed: " + res.decompileCompleted());
        println("TimedOut:  " + res.isTimedOut());
        println("Error:     " + res.getErrorMessage());
        if (res.getDecompiledFunction() != null) {
            println("---- Decompiled C ----");
            println(res.getDecompiledFunction().getC());
        }
    }
}

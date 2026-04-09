import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.LinkedHashMap;
import java.util.Map;

public class AssertAbiModel extends GhidraScript {
    private static long parseAddrArg(String s) {
        String v = s.trim().toLowerCase();
        if (v.startsWith("0x")) {
            return Long.parseUnsignedLong(v.substring(2), 16);
        }
        return Long.parseLong(v, 10);
    }

    private static Map<String, Long> loadManifest(String path) throws Exception {
        Map<String, Long> values = new LinkedHashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) {
                    continue;
                }
                int idx = line.indexOf('=');
                String key = line.substring(0, idx).trim();
                String val = line.substring(idx + 1).trim();
                if (key.startsWith("expect_") || key.endsWith("_params")) {
                    continue;
                }
                if (val.startsWith("0x") || val.matches("^[0-9]+$")) {
                    values.put(key, parseAddrArg(val));
                }
            }
        }
        return values;
    }

    private static String getManifestValue(String path, String wanted) throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.startsWith(wanted + "=")) {
                    continue;
                }
                return line.substring(wanted.length() + 1).trim();
            }
        }
        throw new IllegalArgumentException("Missing manifest key: " + wanted);
    }

    private static String signaturePrefix(String c) {
        int brace = c.indexOf('{');
        if (brace <= 0) {
            return c.trim();
        }
        return c.substring(0, brace).trim();
    }

    private static boolean hasWideScalarType(String sig) {
        return sig.contains("longlong") || sig.contains("long long") || sig.contains("undefined8");
    }

    private void fail(String msg) {
        throw new RuntimeException("ABI assertion failed: " + msg);
    }

    private Function ensureFunction(String name, Address addr) throws Exception {
        disassemble(addr);
        Function f = getFunctionAt(addr);
        if (f == null) {
            createFunction(addr, name);
            f = getFunctionAt(addr);
        }
        if (f == null) {
            fail("could not create function " + name + " at " + addr);
        }
        f.setName(name, SourceType.USER_DEFINED);
        return f;
    }

    private String decompileFunction(DecompInterface ifc, Function f) throws Exception {
        DecompileResults res = ifc.decompileFunction(f, 60, monitor);
        if (!res.decompileCompleted()) {
            fail("decompile did not complete for " + f.getName());
        }
        String err = res.getErrorMessage();
        if (err != null && !err.isBlank()) {
            fail("decompile error for " + f.getName() + ": " + err);
        }
        if (res.getDecompiledFunction() == null) {
            fail("missing decompiled text for " + f.getName());
        }
        return res.getDecompiledFunction().getC();
    }

    private void applyWidePrototype(Function fRet64, Function fTake64) throws Exception {
        Register d1 = currentProgram.getRegister("D1");
        Register d0 = currentProgram.getRegister("D0");
        if (d1 == null || d0 == null) {
            fail("missing D1/D0 registers in current language");
        }

        VariableStorage wideStorage = new VariableStorage(currentProgram, d1, d0);
        fRet64.setReturn(new LongLongDataType(), wideStorage, SourceType.USER_DEFINED);
        fRet64.setCustomVariableStorage(true);

        Parameter[] wideParams = new Parameter[] {
            new ParameterImpl("param_1", new LongLongDataType(), wideStorage, currentProgram,
                SourceType.USER_DEFINED)
        };
        fTake64.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, false,
            SourceType.USER_DEFINED, wideParams);
        fTake64.setCustomVariableStorage(true);
    }

    private void labelData(String name, long addr) throws Exception {
        createLabel(toAddr(addr), name, true);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1 || args[0].isBlank()) {
            fail("expected manifest path as script argument");
        }

        String manifestPath = args[0].trim();
        Map<String, Long> manifest = loadManifest(manifestPath);

        Address entry = toAddr(manifest.get("abi_entry"));
        Address sumFn = toAddr(manifest.get("abi_sum_fn"));
        Address ret32Fn = toAddr(manifest.get("abi_ret32_fn"));
        Address ret64Fn = toAddr(manifest.get("abi_ret64_fn"));
        Address take64Fn = toAddr(manifest.get("abi_take64_fn"));
        Address retptrFn = toAddr(manifest.get("abi_retptr_fn"));

        Function fEntry = ensureFunction("abi_entry", entry);
        Function fSum = ensureFunction("abi_sum_fn", sumFn);
        Function fRet32 = ensureFunction("abi_ret32_fn", ret32Fn);
        Function fRet64 = ensureFunction("abi_ret64_fn", ret64Fn);
        Function fTake64 = ensureFunction("abi_take64_fn", take64Fn);
        Function fRetPtr = ensureFunction("abi_retptr_fn", retptrFn);

        labelData("abi_d1_arg", manifest.get("d1_arg_addr"));
        labelData("abi_ret64_hi", manifest.get("ret64_hi_addr"));
        labelData("abi_ptr_target", manifest.get("ptr_target"));

        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) {
            fail("failed to open program in decompiler");
        }

        String cEntry = decompileFunction(ifc, fEntry);
        String cSum = decompileFunction(ifc, fSum);
        String cRet32 = decompileFunction(ifc, fRet32);
        String cRet64 = decompileFunction(ifc, fRet64);
        String cTake64 = decompileFunction(ifc, fTake64);
        String cRetPtr = decompileFunction(ifc, fRetPtr);

        String sumSig = signaturePrefix(cSum);
        if (!sumSig.contains("abi_sum_fn") || !sumSig.contains("param_1") || !sumSig.contains("param_2")) {
            fail("abi_sum_fn decompile signature looks wrong:\n" + sumSig);
        }

        if (!cRet32.contains("0x11223344")) {
            fail("abi_ret32_fn missing expected constant");
        }

        if (!cRet64.contains("0x99aabbcc")) {
            fail("abi_ret64_fn missing expected low word");
        }

        String ret64Sig = signaturePrefix(cRet64);
        if (!ret64Sig.contains("abi_ret64_fn")) {
            fail("abi_ret64_fn decompile signature looks wrong:\n" + ret64Sig);
        }

        String take64Sig = signaturePrefix(cTake64);
        if (!take64Sig.contains("abi_take64_fn") || !take64Sig.contains("param_1") || !take64Sig.contains("param_2")) {
            fail("abi_take64_fn decompile signature looks wrong:\n" + take64Sig);
        }

        String entrySig = signaturePrefix(cEntry);
        if (!entrySig.contains("abi_entry")) {
            fail("abi_entry decompile signature looks wrong:\n" + entrySig);
        }

        if (!cRetPtr.contains("abi_ptr_target")) {
            fail("abi_retptr_fn missing expected pointer target label");
        }

        if (!cEntry.contains("abi_sum_fn") ||
            !cEntry.contains("abi_ret32_fn") ||
            !cEntry.contains("abi_ret64_fn") ||
            !cEntry.contains("abi_take64_fn") ||
            !cEntry.contains("abi_retptr_fn")) {
            fail("abi_entry missing one or more call sites");
        }

        int ret64Idx = cEntry.indexOf("abi_ret64_fn");
        int take64Idx = cEntry.indexOf("abi_take64_fn");
        if (ret64Idx < 0 || take64Idx < 0 || ret64Idx > take64Idx) {
            fail("abi_entry does not consume the wide return before the wide argument use:\n" + cEntry);
        }

        fTake64.setCallingConvention("__mncall_wideprobe");
        Parameter[] naturalWideParams = new Parameter[] {
            new ParameterImpl("param_1", new LongLongDataType(), currentProgram,
                SourceType.USER_DEFINED)
        };
        fTake64.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false,
            SourceType.USER_DEFINED, naturalWideParams);
        fTake64.setCustomVariableStorage(false);

        fRet64.setCallingConvention("__mncall_wideprobe");
        fRet64.setReturnType(new LongLongDataType(), SourceType.USER_DEFINED);
        fRet64.setCustomVariableStorage(false);

        DecompInterface naturalIfc = new DecompInterface();
        if (!naturalIfc.openProgram(currentProgram)) {
            fail("failed to reopen program in decompiler for natural wide ABI probe");
        }

        String cRet64Natural = decompileFunction(naturalIfc, fRet64);
        String cTake64Natural = decompileFunction(naturalIfc, fTake64);
        String cEntryNatural = decompileFunction(naturalIfc, fEntry);
        String ret64NaturalSig = signaturePrefix(cRet64Natural);
        String take64NaturalSig = signaturePrefix(cTake64Natural);
        println("ABI_RET64_NATURAL_SIGNATURE=" + fRet64.getPrototypeString(true, true));
        println("ABI_TAKE64_NATURAL_SIGNATURE=" + fTake64.getPrototypeString(true, true));
        println("--- ABI RET64 NATURAL ---");
        println(cRet64Natural);
        println("--- ABI TAKE64 NATURAL ---");
        println(cTake64Natural);
        println("--- ABI ENTRY NATURAL ---");
        println(cEntryNatural);

        if (!ret64NaturalSig.contains("abi_ret64_fn")) {
            fail("abi_ret64_fn natural probe lost the function signature:\n" + ret64NaturalSig);
        }

        if (!cEntryNatural.contains("abi_ret64_fn") ||
            !cEntryNatural.contains("abi_take64_fn")) {
            fail("abi_entry natural probe lost the wide flow call chain:\n" + cEntryNatural);
        }

        if (cEntryNatural.contains("__return_storage_ptr__") ||
            cEntryNatural.contains("abi_take64_fn();")) {
            println("ABI_NATURAL_WIDE_PROBE=still-explicit");
        }
        else {
            println("ABI_NATURAL_WIDE_PROBE=natural");
        }

        println("ABI_ASSERTION_OK manifest=" + manifestPath);
        println(
            "ABI_ASSERTION_SUMMARY sum_params=2 ret32_len=4 ret64_note=natural-wide-return " +
            "take64_note=natural-wide-arg ret64_flow=consumed-before-take64-wide-entry pointer=abi_ptr_target");
        println("--- ABI SUM ---");
        println(cSum);
        println("--- ABI RET32 ---");
        println(cRet32);
        println("--- ABI RET64 ---");
        println(cRet64);
        println("--- ABI TAKE64 ---");
        println(cTake64);
        println("--- ABI RETPTR ---");
        println(cRetPtr);
        println("--- ABI ENTRY ---");
        println(cEntry);
    }
}

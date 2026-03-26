import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ReportUnknownOps extends GhidraScript {

    // Touching this file forces headless Ghidra to recompile the script under the active JDK.
    private static final int DEFAULT_TOP_N = 20;
    private static final int DEFAULT_SAMPLES = 10;

    @Override
    protected void run() throws Exception {
        int topN = DEFAULT_TOP_N;
        boolean doLinearSweep = true;

        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            topN = Integer.parseInt(args[0]);
        }
        if (args != null && args.length > 1 && !args[1].isEmpty()) {
            doLinearSweep = !"nosweep".equalsIgnoreCase(args[1]);
        }

        if (doLinearSweep) {
            linearSweepDisassemble();
        }

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(true);

        int total = 0;
        int unknown = 0;
        Map<Integer, Integer> byByte = new HashMap<>();
        Map<Integer, Map<Integer, Integer>> prefixSecondByte = new HashMap<>();
        List<String> samples = new ArrayList<>();

        while (it.hasNext()) {
            Instruction ins = it.next();
            total++;
            if (!"op".equals(ins.getMnemonicString())) {
                continue;
            }
            unknown++;

            int b = -1;
            try {
                byte[] bytes = ins.getBytes();
                if (bytes != null && bytes.length > 0) {
                    b = bytes[0] & 0xff;
                }
            } catch (Exception ignored) {
                // Keep unknown byte marker as -1 if bytes are unavailable.
            }
            byByte.put(b, byByte.getOrDefault(b, 0) + 1);

            if (b >= 0xF0) {
                int b1 = -1;
                try {
                    Address a1 = ins.getAddress().add(1);
                    b1 = currentProgram.getMemory().getByte(a1) & 0xff;
                } catch (Exception ignored) {
                    // Keep marker if byte is unavailable.
                }
                Map<Integer, Integer> pmap = prefixSecondByte.get(b);
                if (pmap == null) {
                    pmap = new HashMap<>();
                    prefixSecondByte.put(b, pmap);
                }
                pmap.put(b1, pmap.getOrDefault(b1, 0) + 1);
            }

            if (samples.size() < DEFAULT_SAMPLES) {
                String text = ins.toString().replace('\n', ' ').replace('\r', ' ');
                samples.add(ins.getAddress() + ":" + text);
            }
        }

        String prog = currentProgram.getName();
        double ratio = total == 0 ? 0.0 : (100.0 * unknown / total);
        println(String.format("UNKNOWN_SUMMARY program=%s total=%d unknown=%d ratio=%.2f%%",
            prog, total, unknown, ratio));

        List<Map.Entry<Integer, Integer>> entries = new ArrayList<>(byByte.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<Integer, Integer>>() {
            @Override
            public int compare(Map.Entry<Integer, Integer> a, Map.Entry<Integer, Integer> b) {
                int c = Integer.compare(b.getValue(), a.getValue());
                if (c != 0) {
                    return c;
                }
                return Integer.compare(a.getKey(), b.getKey());
            }
        });

        int rank = 1;
        for (Map.Entry<Integer, Integer> e : entries) {
            if (rank > topN) {
                break;
            }
            int b = e.getKey();
            String btxt = b >= 0 ? String.format("0x%02x", b) : "NA";
            println(String.format("UNKNOWN_TOP program=%s rank=%d byte=%s count=%d",
                prog, rank, btxt, e.getValue()));
            rank++;
        }

        if (!prefixSecondByte.isEmpty()) {
            List<Integer> prefixes = new ArrayList<>(prefixSecondByte.keySet());
            Collections.sort(prefixes);

            for (Integer pfx : prefixes) {
                Map<Integer, Integer> pmap = prefixSecondByte.get(pfx);
                List<Map.Entry<Integer, Integer>> entries2 = new ArrayList<>(pmap.entrySet());
                Collections.sort(entries2, new Comparator<Map.Entry<Integer, Integer>>() {
                    @Override
                    public int compare(Map.Entry<Integer, Integer> a, Map.Entry<Integer, Integer> b) {
                        int c = Integer.compare(b.getValue(), a.getValue());
                        if (c != 0) {
                            return c;
                        }
                        return Integer.compare(a.getKey(), b.getKey());
                    }
                });

                int rank2 = 1;
                for (Map.Entry<Integer, Integer> e : entries2) {
                    if (rank2 > topN) {
                        break;
                    }
                    int b1 = e.getKey();
                    String b1txt = b1 >= 0 ? String.format("0x%02x", b1) : "NA";
                    println(String.format("UNKNOWN_PFX_B1 program=%s pfx=0x%02x rank=%d b1=%s count=%d",
                        prog, pfx, rank2, b1txt, e.getValue()));
                    rank2++;
                }
            }
        }

        for (String s : samples) {
            println(String.format("UNKNOWN_SAMPLE program=%s %s", prog, s));
        }
    }

    private void linearSweepDisassemble() throws Exception {
        Listing listing = currentProgram.getListing();
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            Address cur = block.getStart();
            Address end = block.getEnd();

            while (cur != null && cur.compareTo(end) <= 0) {
                monitor.checkCancelled();

                Instruction existing = listing.getInstructionAt(cur);
                if (existing != null) {
                    cur = existing.getMaxAddress().next();
                    continue;
                }

                disassemble(cur);
                Instruction ins = listing.getInstructionAt(cur);
                if (ins != null) {
                    cur = ins.getMaxAddress().next();
                } else {
                    cur = cur.next();
                }
            }
        }
    }
}

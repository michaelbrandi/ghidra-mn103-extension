# PrintEntryInstructions.py
# @category mn103


def parse_addr(value):
    v = value.strip().lower()
    if v.startswith("0x"):
        return int(v[2:], 16)
    return int(v, 10)


entry = toAddr(0x2000)
entry_sym = getSymbol("entry", None)
if entry_sym is not None:
    entry = entry_sym.getAddress()

args = getScriptArgs()
if args and len(args) > 0 and args[0].strip():
    entry = toAddr(parse_addr(args[0]))

print("Program: %s" % currentProgram.getName())
print("Entry: %s" % entry)

disassemble(entry)

listing = currentProgram.getListing()
inst = listing.getInstructionAt(entry)
count = 0
max_count = 80
while inst is not None and count < max_count:
    print("%s: %s" % (inst.getAddress(), inst))
    inst = inst.getNext()
    count += 1

print("Printed %d instructions" % count)

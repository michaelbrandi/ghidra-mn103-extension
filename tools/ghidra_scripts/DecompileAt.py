# DecompileAt.py
# @category mn103

from ghidra.app.decompiler import DecompInterface


def parse_addr(value):
    v = value.strip().lower()
    if v.startswith("0x"):
        return int(v[2:], 16)
    return int(v, 10)


target = toAddr(0x2000)
args = getScriptArgs()
if args and len(args) > 0 and args[0].strip():
    target = toAddr(parse_addr(args[0]))

func = getFunctionContaining(target)
if func is None:
    disassemble(target)
    createFunction(target, None)
    func = getFunctionContaining(target)

if func is None:
    print("No function found at %s" % target)
    exit()

iface = DecompInterface()
iface.openProgram(currentProgram)

result = iface.decompileFunction(func, 60, monitor)
print("Function: %s @ %s" % (func.getName(), func.getEntryPoint()))
print("Completed: %s" % result.decompileCompleted())
print("TimedOut: %s" % result.isTimedOut())
err = result.getErrorMessage()
print("Error: %s" % (err if err else ""))

if result.decompileCompleted():
    dfunc = result.getDecompiledFunction()
    if dfunc is not None:
        print("--- Decompiled C ---")
        print(dfunc.getC())

// Establish a profile-validated console entry for static CPU analysis.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class PrepareConsoleEntry extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected one reset address");
        long entry = Long.decode(args[0]);
        if (entry < 0 || entry > 0xffffffffL) throw new IllegalArgumentException("Invalid console entry address");
        Address address = toAddr(entry);
        if (!currentProgram.getMemory().contains(address)) throw new IllegalArgumentException("Unmapped reset entry");
        currentProgram.getSymbolTable().addExternalEntryPoint(address);
        disassemble(address);
        if (getFunctionAt(address) == null) createFunction(address, "module_entry");
    }
}

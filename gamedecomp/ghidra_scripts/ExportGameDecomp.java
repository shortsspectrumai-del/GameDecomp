// Export decompiler evidence. No recovered input code is executed.
// @category GameDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ExternalLocation;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportGameDecomp extends GhidraScript {
    private static final int MAX_PREAMBLE_BYTES = 262144;
    private static final int MAX_EXPORT_BYTES = 128 * 1024 * 1024;

    private static class BoundedWriter extends Writer {
        private final StringBuilder text = new StringBuilder();
        private int bytes = 0;
        @Override public void write(char[] chars, int offset, int length) throws IOException {
            String part = new String(chars, offset, length);
            int size = part.getBytes(StandardCharsets.UTF_8).length;
            if (size > MAX_PREAMBLE_BYTES - bytes) throw new IOException("Compilation context exceeds 256 KiB");
            bytes += size;
            text.append(part);
        }
        @Override public void flush() {}
        @Override public void close() {}
        @Override public String toString() { return text.toString(); }
    }

    private static class Recovered {
        final Function function;
        final DecompileResults result;
        final String source;
        Recovered(Function f, DecompileResults r) {
            function = f;
            result = r;
            source = r.decompileCompleted() && r.getDecompiledFunction() != null
                ? r.getDecompiledFunction().getC() : null;
        }
    }

    // Render only the observed datatype. No guessed C headers or signatures are added.
    private String declaration(DataType type, String name, int depth) throws IOException {
        if (depth > 64 || type == null) throw new IOException("Unsupported or recursive global datatype");
        if (type instanceof Array array) {
            return declaration(array.getDataType(), name + "[" + array.getNumElements() + "]", depth + 1);
        }
        if (type instanceof Pointer pointer) {
            DataType target = pointer.getDataType();
            String pointerName = "*" + name;
            if (target instanceof Array || target instanceof FunctionDefinition) pointerName = "(" + pointerName + ")";
            if (target == null) return "void " + pointerName;
            return declaration(target, pointerName, depth + 1);
        }
        if (type instanceof FunctionDefinition definition) {
            List<String> args = new ArrayList<>();
            for (ParameterDefinition parameter : definition.getArguments()) {
                args.add(declaration(parameter.getDataType(), "", depth + 1));
            }
            if (definition.hasVarArgs()) args.add("...");
            else if (args.isEmpty()) args.add("void");
            return declaration(definition.getReturnType(), name + "(" + String.join(",", args) + ")", depth + 1);
        }
        if (type instanceof Dynamic || type instanceof FactoryDataType || type instanceof BitFieldDataType) {
            throw new IOException("Unsupported global datatype");
        }
        return type.getDisplayName() + " " + name;
    }

    private String compilationPreamble(Recovered recovered, Map<Address, Recovered> all) throws Exception {
        if (recovered.source == null || recovered.result.getHighFunction() == null) {
            throw new IOException("No complete decompiler context");
        }
        String identifiers = recovered.source.replaceAll(
            "(?s)/\\*.*?\\*/|//[^\\r\\n]*|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'", "");
        if (identifiers.contains("::")) {
            throw new IOException("Scoped identifiers require a C++ declaration context; C context unavailable");
        }
        BoundedWriter writer = new BoundedWriter();
        List<DataType> types = new ArrayList<>();
        types.add(recovered.function.getReturnType());
        for (Variable variable : recovered.function.getAllVariables()) types.add(variable.getDataType());
        Iterator<HighSymbol> locals = recovered.result.getHighFunction().getLocalSymbolMap().getSymbols();
        while (locals.hasNext()) types.add(locals.next().getDataType());
        List<ClangNode> tokens = new ArrayList<>();
        recovered.result.getCCodeMarkup().flatten(tokens);
        for (ClangNode token : tokens) {
            if (token instanceof ClangTypeToken typeToken) types.add(typeToken.getDataType());
        }
        Set<String> globals = new TreeSet<>();
        Iterator<HighSymbol> symbols = recovered.result.getHighFunction().getGlobalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            HighSymbol symbol = symbols.next();
            if (!symbol.getName().matches("[A-Za-z_][A-Za-z_0-9]*")) {
                throw new IOException("Global name cannot be represented as a C identifier");
            }
            types.add(symbol.getDataType());
            globals.add("extern " + declaration(symbol.getDataType(), symbol.getName(), 0) + ";\n");
        }
        Set<String> prototypes = new TreeSet<>();
        for (Function called : recovered.function.getCalledFunctions(monitor)) {
            monitor.checkCancelled();
            if (called.getEntryPoint().equals(recovered.function.getEntryPoint())) continue;
            types.add(called.getReturnType());
            for (Parameter parameter : called.getParameters()) types.add(parameter.getDataType());
            Recovered target = all.get(called.getEntryPoint());
            // The decompiled signature can differ from the listing signature
            // (notably an inferred bool return in stripped programs). Collect
            // the same types as the signature that is actually emitted below.
            if (target != null && target.result.getHighFunction() != null) {
                var prototype = target.result.getHighFunction().getFunctionPrototype();
                types.add(prototype.getReturnType());
                for (int index = 0; index < prototype.getNumParams(); index++) {
                    HighSymbol parameter = prototype.getParam(index);
                    if (parameter == null) throw new IOException("Incomplete inferred callee parameter types");
                    types.add(parameter.getDataType());
                }
            }
            String prototype = target != null && target.result.getDecompiledFunction() != null
                ? target.result.getDecompiledFunction().getSignature()
                : called.getPrototypeString(false, false);
            prototypes.add(prototype + (prototype.stripTrailing().endsWith(";") ? "\n" : ";\n"));
        }
        BoundedWriter typeWriter = new BoundedWriter();
        DataTypeWriter dataTypes = new DataTypeWriter(currentProgram.getDataTypeManager(), typeWriter);
        dataTypes.write(types, monitor);
        // Keep Ghidra's observed unsigned-char bool representation. stdbool.h's
        // macro would otherwise rewrite its typedef to the C11 keyword _Bool.
        // _Bool itself is intrinsic in C11 and must not be redefined by DWARF.
        writer.write("#include <stdbool.h>\n#undef bool\n");
        for (String line : typeWriter.toString().split("\\n", -1)) {
            if (line.matches("\\s*typedef\\s+[^;]+\\s+_Bool\\s*;\\s*")) {
                writer.write("/* C11 intrinsic _Bool: redundant exported typedef omitted. */\n");
            } else {
                writer.write(line + "\n");
            }
        }
        for (String global : globals) writer.write(global);
        for (String prototype : prototypes) writer.write(prototype);
        return writer.toString();
    }

    private String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 32 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private String utf8Prefix(String value, int maximum) {
        int end = 0;
        int size = 0;
        while (end < value.length()) {
            int next = end + Character.charCount(value.codePointAt(end));
            int bytes = value.substring(end, next).getBytes(StandardCharsets.UTF_8).length;
            if (size + bytes > maximum) break;
            size += bytes;
            end = next;
        }
        return value.substring(0, end);
    }

    // These are static references recorded by Ghidra, not runtime observations.
    // Only defined strings at the exact target are read; no global string scan,
    // interior-string guessing or emulation is used to invent missing targets.
    private class BinaryReferences {
        final List<String> records = new ArrayList<>();
        final Set<String> seen = new HashSet<>();
        int bytes = 2;
        int scannedInstructions = 0;
        int scannedReferences = 0;
        int omitted = 0;
        boolean truncated = false;

        private void add(String record) {
            if (!seen.add(record)) return;
            int size = record.getBytes(StandardCharsets.UTF_8).length + 1;
            if (records.size() >= 256 || size > 65536 - bytes) {
                omitted++;
                truncated = true;
                return;
            }
            records.add(record);
            bytes += size;
        }

        void observe(Instruction instruction) throws Exception {
            if (scannedReferences >= 4096) {
                truncated = true;
                return;
            }
            scannedInstructions++;
            for (Reference reference : instruction.getReferencesFrom()) {
                monitor.checkCancelled();
                if (scannedReferences >= 4096) {
                    truncated = true;
                    break;
                }
                scannedReferences++;
                Address target = reference.getToAddress();
                String common = ",\"from_address\":" + Long.toUnsignedString(instruction.getAddress().getOffset())
                    + ",\"to_address\":" + Long.toUnsignedString(target.getOffset())
                    + ",\"to_address_space\":" + q(target.getAddressSpace().getName())
                    + ",\"operand_index\":" + reference.getOperandIndex()
                    + ",\"reference_type\":" + q(reference.getReferenceType().toString());
                Data data = currentProgram.getListing().getDefinedDataAt(target);
                if (data != null && data.hasStringValue()) {
                    // Bound decoding itself as well as the exported excerpt.
                    if (data.getLength() <= 0 || data.getLength() > 4096) {
                        omitted++;
                        truncated = true;
                    } else if (data.getValue() instanceof String value) {
                        int originalBytes = value.getBytes(StandardCharsets.UTF_8).length;
                        String prefix = utf8Prefix(value, 1024);
                        add("{\"kind\":\"string_reference\"" + common
                            + ",\"value\":" + q(prefix)
                            + ",\"text_truncated\":" + !prefix.equals(value)
                            + ",\"original_text_bytes\":" + originalBytes + "}");
                    }
                }
                Function called = currentProgram.getFunctionManager().getReferencedFunction(target);
                boolean viaThunk = false;
                Set<Address> visited = new HashSet<>();
                int depth = 0;
                while (called != null && !called.isExternal() && called.isThunk()) {
                    if (!visited.add(called.getEntryPoint()) || depth++ >= 16) {
                        called = null;
                        omitted++;
                        truncated = true;
                        break;
                    }
                    viaThunk = true;
                    called = called.getThunkedFunction(false);
                }
                if (called != null && called.isExternal()) {
                    ExternalLocation location = called.getExternalLocation();
                    String library = location == null ? "" : location.getLibraryName();
                    if (library == null) library = "";
                    String name = called.getName();
                    if (name.getBytes(StandardCharsets.UTF_8).length > 256
                            || library.getBytes(StandardCharsets.UTF_8).length > 256) {
                        omitted++;
                        truncated = true;
                        continue;
                    }
                    add("{\"kind\":\"external_function_reference\"" + common
                        + ",\"target_name\":" + q(name) + ",\"library\":" + q(library)
                        + ",\"via_thunk\":" + viaThunk + "}");
                }
            }
        }

        String summary(boolean instructionsTruncated) {
            return "{\"source\":\"Ghidra ReferenceManager\",\"version\":1"
                + ",\"scanned_instructions\":" + scannedInstructions
                + ",\"scanned_references\":" + scannedReferences
                + ",\"emitted\":" + records.size() + ",\"omitted\":" + omitted
                + ",\"scan_truncated\":" + (truncated || instructionsTruncated) + "}";
        }
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Output path required");
        DecompInterface d = new DecompInterface();
        StringBuilder b = new StringBuilder();
        b.append("{\"binary_hash\":\"\",\"format\":").append(q(currentProgram.getExecutableFormat()));
        b.append(",\"architecture\":").append(q(currentProgram.getLanguageID().toString()));
        b.append(",\"backend\":\"ghidra\",\"diagnostics\":[],\"metadata\":{\"frontend_version\":")
            .append(q(Application.getApplicationVersion())).append(",\"image_base\":")
            .append(Long.toUnsignedString(currentProgram.getImageBase().getOffset()))
            .append(",\"semantic_status\":\"UNKNOWN\"},\"functions\":[");
        boolean first = true;
        try {
            if (!d.openProgram(currentProgram)) throw new IllegalStateException("Decompiler open failed");
            Map<Address, Recovered> recovered = new LinkedHashMap<>();
            FunctionIterator fs = currentProgram.getFunctionManager().getFunctions(true);
            int sourceBytes = 0;
            while (fs.hasNext()) {
                monitor.checkCancelled();
                Function f = fs.next();
                if (f.isExternal()) continue;
                Recovered entry = new Recovered(f, d.decompileFunction(f, 30, monitor));
                sourceBytes += entry.source == null ? 0 : entry.source.getBytes(StandardCharsets.UTF_8).length;
                if (sourceBytes > MAX_EXPORT_BYTES || recovered.size() >= 20000) {
                    throw new IOException("Decompiler export exceeds bounded size");
                }
                recovered.put(f.getEntryPoint(), entry);
            }
            for (Recovered entry : recovered.values()) {
                monitor.checkCancelled();
                Function f = entry.function;
                if (!first) b.append(',');
                first = false;
                String address = Long.toUnsignedString(f.getEntryPoint().getOffset());
                String id = "native:" + f.getEntryPoint().toString();
                DecompileResults result = entry.result;
                String source = entry.source;
                String preamble = "";
                String preambleStatus = "UNAVAILABLE";
                String preambleDiagnostic = "";
                try {
                    preamble = compilationPreamble(entry, recovered);
                    preambleStatus = "AVAILABLE";
                } catch (IOException | IllegalArgumentException error) {
                    preambleDiagnostic = error.getMessage();
                }
                b.append("{\"id\":").append(q(id)).append(",\"name\":").append(q(f.getName()));
                b.append(",\"address\":").append(address).append(",\"source\":").append(q(source));
                b.append(",\"diagnostics\":[");
                if (source == null) b.append(q(result.getErrorMessage()));
                b.append("],\"calls\":[");
                boolean firstCall = true;
                for (Function called : f.getCalledFunctions(monitor)) {
                    if (!firstCall) b.append(',');
                    firstCall = false;
                    b.append(q("native:" + called.getEntryPoint().toString()));
                }
                b.append("],\"instructions\":[");
                InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(), true);
                BinaryReferences references = new BinaryReferences();
                int count = 0;
                while (ins.hasNext() && count < 40000) {
                    Instruction i = ins.next();
                    references.observe(i);
                    if (count++ > 0) b.append(',');
                    StringBuilder operands = new StringBuilder();
                    for (int n = 0; n < i.getNumOperands(); n++) {
                        if (n > 0) operands.append(", ");
                        operands.append(i.getDefaultOperandRepresentation(n));
                    }
                    b.append("{\"address\":").append(Long.toUnsignedString(i.getAddress().getOffset()));
                    b.append(",\"mnemonic\":").append(q(i.getMnemonicString()));
                    b.append(",\"operands\":").append(q(operands.toString())).append('}');
                }
                b.append("],\"metadata\":{\"language\":\"c\",\"original_symbol\":").append(q(f.getName()));
                b.append(",\"instruction_limit\":40000,\"instructions_truncated\":").append(ins.hasNext());
                b.append(",\"binary_references\":[").append(String.join(",", references.records)).append(']');
                b.append(",\"binary_reference_summary\":").append(references.summary(ins.hasNext()));
                b.append(",\"signature\":").append(q(f.getSignature().toString())).append(",\"pcode\":[");
                if (result.getHighFunction() != null) {
                    Iterator<PcodeOpAST> ops = result.getHighFunction().getPcodeOps();
                    int n = 0;
                    while (ops.hasNext() && n < 8192) {
                        if (n++ > 0) b.append(',');
                        b.append(q(ops.next().toString()));
                    }
                    b.append("],\"pcode_truncated\":").append(ops.hasNext());
                } else b.append(']');
                b.append(",\"compile_preamble\":").append(q(preamble));
                b.append(",\"compile_preamble_status\":").append(q(preambleStatus));
                b.append(",\"compile_preamble_diagnostic\":").append(q(preambleDiagnostic));
                b.append(",\"semantic_status\":\"UNKNOWN\"}}");
                if (b.length() > MAX_EXPORT_BYTES) throw new IOException("Decompiler JSON export exceeds bounded size");
            }
        } finally { d.dispose(); }
        b.append("]}");
        byte[] output = b.toString().getBytes(StandardCharsets.UTF_8);
        if (output.length > MAX_EXPORT_BYTES) throw new IOException("Decompiler JSON export exceeds 128 MiB");
        Files.write(Path.of(args[0]), output);
    }
}

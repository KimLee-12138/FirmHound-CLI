// ExportCfgCg.java - Ghidra headless post-script for FirmHound mini-BOND.
// @category FirmHound

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportCfgCg extends GhidraScript {
    private static String q(String value) {
        if (value == null) return "null";
        String escaped = value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t");
        return "\"" + escaped + "\"";
    }

    private static String stringsJson(Iterable<String> values) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) out.append(',');
            out.append(q(value));
            first = false;
        }
        return out.append(']').toString();
    }

    private static String address(Address value) {
        return "0x" + Long.toUnsignedString(value.getOffset(), 16);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("ExportCfgCg.java requires one output path");
        }

        Listing listing = currentProgram.getListing();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        Map<String, String> functionsJson = new LinkedHashMap<>();
        Map<String, Set<String>> callgraph = new LinkedHashMap<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            String address = address(function.getEntryPoint());
            Set<String> callees = new LinkedHashSet<>();
            Set<String> strings = new LinkedHashSet<>();
            List<String> blocks = new ArrayList<>();

            CodeBlockIterator blockIterator = blockModel.getCodeBlocksContaining(
                function.getBody(), monitor
            );
            while (blockIterator.hasNext()) {
                CodeBlock block = blockIterator.next();
                blocks.add(
                    "{\"start\":" + q(address(block.getFirstStartAddress()))
                    + ",\"end\":" + q(address(block.getMaxAddress())) + "}"
                );
            }

            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    Address target = reference.getToAddress();
                    if (reference.getReferenceType().isCall()) {
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                        if (callee == null) {
                            callee = currentProgram.getFunctionManager().getFunctionContaining(target);
                        }
                        if (callee != null) callees.add(address(callee.getEntryPoint()));
                    }
                    if (reference.getReferenceType().isData()) {
                        Data data = listing.getDataAt(target);
                        if (data != null) {
                            DataType type = data.getDataType();
                            String typeName = type == null ? "" : type.getName().toLowerCase();
                            if (typeName.contains("string")) {
                                strings.add(data.getDefaultValueRepresentation());
                            }
                        }
                    }
                }
            }

            callgraph.put(address, callees);
            String functionJson = "{\"name\":" + q(function.getName())
                + ",\"strings\":" + stringsJson(strings)
                + ",\"basic_blocks\":[" + String.join(",", blocks) + "]}";
            functionsJson.put(address, functionJson);
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"available\":true,\"program\":")
            .append(q(currentProgram.getName())).append(",\"functions\":{");
        boolean first = true;
        for (Map.Entry<String, String> item : functionsJson.entrySet()) {
            if (!first) json.append(',');
            json.append(q(item.getKey())).append(':').append(item.getValue());
            first = false;
        }
        json.append("},\"callgraph\":{");
        first = true;
        for (Map.Entry<String, Set<String>> item : callgraph.entrySet()) {
            if (!first) json.append(',');
            json.append(q(item.getKey())).append(':').append(stringsJson(item.getValue()));
            first = false;
        }
        json.append("}}");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(args[0]))) {
            writer.write(json.toString());
        }
        println("FirmHound CFG/CG export written to " + args[0]);
    }
}

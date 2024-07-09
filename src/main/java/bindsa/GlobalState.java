package bindsa;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import bindsa.CallSiteNode;
import bindsa.Cell;
import bindsa.DSNode;
import bindsa.DebugUtil;
import bindsa.GlobalRegion;
import bindsa.Graph;
import bindsa.Pair;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class GlobalState {
	public static DecompInterface decomplib;
	public static int TOP = Integer.MAX_VALUE;
	public static String targetPath = System.getProperty("user.home") + "/spec2006x86/O2_out/targets.txt";
	public static String outPath = System.getProperty("user.home") + "/spec2006x86/O2_out/solved_copy.txt";
	public static String decompiledPath = System.getProperty("user.home") + "/spec2006x86/decompiled/";
	public static String memAccessPath = System.getProperty("user.home") + "/spec2006x86/O2_out/mem_access.txt";
	public static HashSet<Function> targetFuncSuperSet = new HashSet<Function>();
	public static boolean conductCollapse = true;
	public static Program currentProgram;
	public static boolean isBottomUp = false;

	public static HashSet<Address> getPossibleFuncPointer(HashSet<Address> allpointers, Program curProgram) {
		HashSet<Address> fps = new HashSet<Address>();
		for (Address p : allpointers) {
			Address memAddr = isFuncPointer(p, curProgram);
			if (memAddr != null)
				fps.add(memAddr);
		}
		return fps;
	}

	public static Address isFuncPointer(Address p, Program curProgram) {
		Address memAddr = curProgram.getAddressFactory()
				.getAddress(curProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(), p.getOffset());
		Function fp = curProgram.getFunctionManager().getFunctionAt(memAddr);
		if (fp != null) {
			GlobalState.targetFuncSuperSet.add(fp);
			return memAddr;
		}
		return null;
	}
}


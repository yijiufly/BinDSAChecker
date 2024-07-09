package bindsa.checkers;

import java.util.ArrayList;
import java.util.HashSet;

import bindsa.Cell;
import bindsa.DSNode;
import bindsa.DebugUtil;
import funcs.libcfuncs.FreeFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class MemChecker {

	public Program currentProgram;
	public static HashSet<Address> cwe416 = new HashSet<Address>();   // use after free
	public static HashSet<Address> cwe415 = new HashSet<Address>();  // double free
	
	public MemChecker() {
	}

	public static void checkExternalCallParameters(Address addr, Function calleeFunc, Cell cell) {
		String functionName = calleeFunc.getName(false);
        if (FreeFunction.getStaticSymbols().contains(functionName)) {
            DSNode ptr = cell.getParent();
            if (!ptr.isValid() && addr != ptr.getFreedAddr())
            	cwe415.add(addr);
            else
            	ptr.setNoValid(addr);
        }
	}
	
	public static void checkMemVuls(Cell c, Address addr) {
		DSNode ptr = c.getParent();
		if (ptr == null)
			return;
		if (ptr.getMemAccessInstr().contains(addr))
			return;
		if (!ptr.isValid() && ptr.getOnHeap())
			cwe416.add(addr);
		ptr.addMemAccessInstr(addr);
	}
	
	public static void print() {
		for (Address a: cwe416) {
			DebugUtil.print("CWE416: " + a.toString());
		}
		for (Address a: cwe415) {
			DebugUtil.print("CWE415: " + a.toString());
		}
	}
	
}

package bindsa.checkers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import bindsa.Cell;
import bindsa.Graph;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class NPDChecker {

	public Program currentProgram;
	private HashMap<Function, Graph> allBUGraphs;
	
	public NPDChecker(Program currentProgram, HashMap<Function, Graph> allBUGraphs) {
		super();
		this.currentProgram = currentProgram;
		this.allBUGraphs = allBUGraphs;
	}

	public static void check() {
		
	}
	
	public void analyzeFuncs(HighFunction hfunction) {
		Function f = hfunction.getFunction();
		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();

		if (bb.size() == 0)
			return;

		Graph graph = allBUGraphs.get(f);

		for (PcodeBlockBasic pBB : bb) {
			Iterator<PcodeOp> opIter = pBB.getIterator();

			while (opIter.hasNext()) {
				PcodeOp pcodeOp = opIter.next();
				boolean hasvul = visit(pcodeOp, graph);
			}
		}
	}
	
	public boolean visit(PcodeOp pcodeOp, Graph graph) {
		switch (pcodeOp.getOpcode()) {
		case PcodeOp.LOAD:
		case PcodeOp.STORE:
			Cell mem = graph.getCell(pcodeOp.getInput(1));
			if (mem.getParent().isGlobal() && mem.getParent().getConstants() != null) {
				if (mem.getParent().getConstants() == 0)
					return true;
			}
			if (mem.getParent().getLocations().size() == 0) {
				return true;
			}
			break;
		case PcodeOp.CALL:
		case PcodeOp.CALLIND:
			Address addr = pcodeOp.getInput(0).getAddress();
			Function fp = this.currentProgram.getFunctionManager().getFunctionAt(addr);
			if (fp != null && fp.isExternal()) {
				for (int i = 1; i < pcodeOp.getNumInputs(); ++i) {
					Varnode arg = pcodeOp.getInput(i);
					Cell argCell = graph.getCell(arg);
					if (arg.getHigh().getDataType().equals(PointerDataType.dataType)) {
						if (argCell.getOutEdges() == null)
							return true;
					}
				}
			}
			break;
		}
		return false;
	}
}

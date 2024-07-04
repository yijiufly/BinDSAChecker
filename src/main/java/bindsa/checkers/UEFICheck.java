package bindsa.checkers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import ghidra.program.model.listing.Function;

public class UEFICheck {

	/*
	public void getAllCallees(Function entry, HashSet<Function> funcSet) {
		if (funcSet.contains(entry))
			return;
		funcSet.add(entry);
		for (Function callee : getCalledFunctions(entry, monitor)) {
			getAllCallees(callee, funcSet);
		}
	}
	
	public void UEFICheck(Function entry, ArrayList<Function> smiHandlers) {
		HashMap<Function, Integer> val = new HashMap<Function, Integer>();
		HashMap<Function, Integer> low = new HashMap<Function, Integer>();
		HashMap<Function, Boolean> inStack = new HashMap<Function, Boolean>();
		ArrayList<Function> stack = new ArrayList<Function>();
		HashSet<Function> funcSet = new HashSet<Function>();
		getAllCallees(entry, funcSet);
		propagateTaint = false;
		for (Function func : funcSet) {
			// local analysis phase
			analyzeLocalFuncs(func);
			val.put(func, -1);
			low.put(func, -1);
			inStack.put(func, false);
			allBUGraphs.put(func, allLocalGraphs.get(func));
		}

//		for (Function func : funcSet) {
//			if (val.containsKey(func) && val.get(func) == -1) {
//				tarjanVisitNode(func, inStack, low, val, stack);
//			}
//		}
//		
//		for (Cell global : allGlobals.values()) {
//			Cell inEdgeOrigin = global.getInMemEdges();
//			if (inEdgeOrigin != null && inEdgeOrigin.getParent() != null) {
//				if (inEdgeOrigin.getWriteFunc().size() == 0)
//					inEdgeOrigin.setTainted(true);
//			}
//		}

		propagateTaint = true;
		for (Function smiHandler : smiHandlers) {
			funcSet = new HashSet<Function>();
			getAllCallees(smiHandler, funcSet);
			for (Function func : funcSet) {
				// local analysis phase
				if (!allLocalGraphs.containsKey(func))
					analyzeLocalFuncs(func);
				val.put(func, -1);
				low.put(func, -1);
				inStack.put(func, false);
				if (!allBUGraphs.containsKey(func))
					allBUGraphs.put(func, allLocalGraphs.get(func));
			}

			// taint for commonbuff
			if (allBUGraphs.get(smiHandler).getArgCell().size() >= 3)
				allBUGraphs.get(smiHandler).getArgCell(2).getParent().setTainted(true);

			for (Function func : funcSet) {
				if (val.containsKey(func) && val.get(func) == -1) {
					tarjanVisitNode(func, inStack, low, val, stack);
				}
			}
		}

	}
	*/
}

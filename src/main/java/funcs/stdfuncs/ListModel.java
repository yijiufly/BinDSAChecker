package funcs.stdfuncs;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import bindsa.Cell;
import bindsa.DSNode;
import bindsa.DebugUtil;
import bindsa.GlobalState;
import bindsa.Graph;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

/**
 * std::list
 */
public class ListModel extends CppStdModelBase {

    private static final Set<String> staticSymbols = Set.of("list");

    public ListModel() {
        super(staticSymbols);
    }

    private void pushBack(PcodeOp pcode, Graph g, Function callFunc) {
        if (callFunc.getParameterCount() != 2) {
            DebugUtil.print("Wrong parameter for: " + callFunc);
            return;
        }
        Cell thisCell = g.getCell(pcode.getInput(1));
        DSNode thisParent = thisCell.getParent();
        int key = Collections.max(thisParent.getMembers().keySet());
        Cell elemCell = g.getCell(pcode.getInput(2));
        thisParent.getOrCreateCell(key + GlobalState.currentProgram.getDefaultPointerSize()).merge(elemCell);
    }

    private Cell back(PcodeOp pcode, Graph g, Function callFunc) {
        if (callFunc.getParameterCount() != 1) {
        	DebugUtil.print("Wrong parameter for: " + callFunc);
            return null;
        }
        
        Cell thisCell = g.getCell(pcode.getInput(1));
        DSNode thisParent = thisCell.getParent();
        int key = Collections.max(thisParent.getMembers().keySet());
        return thisParent.get(key);
    }

    public Cell invoke(PcodeOp pcode, Graph g, Function callFunc) {
    	DebugUtil.print("Invoke std::list::" + callFunc.getName());
    	Cell ret = null;
        switch (callFunc.getName()) {
            case "list":
                if (callFunc.getParameterCount() == 1) {
                	invokeConstructor(pcode, g, callFunc);
                } else if (callFunc.getParameterCount() == 2) {
                	invokeCopyConstructor(pcode, g, callFunc);
                }
                break;
            case "push_back":
                pushBack(pcode, g, callFunc);
                break;
            case "back":
            	ret = back(pcode, g, callFunc);
                break;
            case "~list":
                invokeDestructor(pcode, g, callFunc);
                break;
            default: // fallthrough
        }
        return ret;
    }

}

package funcs.libcfuncs;

import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class FreeFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("free", "operator.delete", "operator.delete[]");

    public FreeFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        setReturnType(VoidDataType.dataType);
    }
    
    @Override
	public void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc) {
		// TODO Auto-generated method stub
		
	}
}
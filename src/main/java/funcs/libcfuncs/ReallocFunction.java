package funcs.libcfuncs;

import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class ReallocFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("realloc");

    public ReallocFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

	@Override
	public void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc) {
		// TODO Auto-generated method stub
		
	}

}

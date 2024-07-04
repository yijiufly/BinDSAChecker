package funcs.libcfuncs;

import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class CallocFunction extends ExternalFunctionBase {

	private static final Set<String> staticSymbols = Set.of("calloc");
	
	public CallocFunction() {
		super(staticSymbols);
		addDefaultParam("nitems", IntegerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
	}

	@Override
	public void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc) {
		// TODO Auto-generated method stub

	}

}

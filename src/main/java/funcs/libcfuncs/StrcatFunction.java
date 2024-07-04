package funcs.libcfuncs;

import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class StrcatFunction extends ExternalFunctionBase {

    // TODO: maybe separate "strncat" to another model for better precision.
    private static final Set<String> staticSymbols = Set.of("strcat", "strncat");

    public StrcatFunction() {
        super(staticSymbols);
        addDefaultParam("dest", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
	public void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc) {
		// TODO Auto-generated method stub
		
	}
}

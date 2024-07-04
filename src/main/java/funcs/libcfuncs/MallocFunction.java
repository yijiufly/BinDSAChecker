package funcs.libcfuncs;

import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class MallocFunction extends ExternalFunctionBase {

	private static final Set<String> staticSymbols = Set.of("malloc", "operator.new", "operator.new[]", "xmalloc");
	
	public MallocFunction() {
		super(staticSymbols);
		// TODO Auto-generated constructor stub
	}

	@Override
	public void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc) {
		// TODO Auto-generated method stub

	}

}

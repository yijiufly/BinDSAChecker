package funcs.libcfuncs;

import java.util.ArrayList;
import java.util.Set;

import bindsa.Cell;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public abstract class ExternalFunctionBase {

	public ExternalFunctionBase(Set<String> symbols) {
        this.symbols = symbols;
    }

    protected Set<String> symbols;

    protected ArrayList<ParameterDefinitionImpl> defaultParameters = new ArrayList<>();

    protected DataType returnType;
    
	protected void addDefaultParam(String name, DataType type) {
        ParameterDefinitionImpl param = new ParameterDefinitionImpl(name, type, name);
        defaultParameters.add(param);
    }
	
	protected void setReturnType(DataType returnType) {
        this.returnType = returnType;
    }
	
	/**
     * Get symbols of the function model.
     * @return a set of symbol strings.
     */
    public Set<String> getSymbols() {
        return symbols;
    }
	
	public abstract void invoke(PcodeOp pcode, Cell inOutEnv, Cell tmpEnv, Function calleeFunc);
	
}

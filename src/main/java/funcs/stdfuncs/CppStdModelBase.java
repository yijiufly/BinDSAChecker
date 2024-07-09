package funcs.stdfuncs;


import java.util.HashMap;
import java.util.List;
import java.util.Set;

import bindsa.Cell;
import bindsa.DebugUtil;
import bindsa.GlobalState;
import bindsa.Graph;
import bindsa.Location;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** The base class of all cpp std function models
 * @param <T>
 */
public abstract class CppStdModelBase {

    static class Signature {

        private List<ParameterDefinitionImpl> defaultParameters;
        private DataType returnType;

        public Signature(List<ParameterDefinitionImpl> defaultParameters, DataType returnType) {
            this.defaultParameters = defaultParameters;
            this.returnType = returnType;
        }
    }

    protected HashMap<String, Signature> signatureHashMap = new HashMap<>();

    protected Set<String> symbols;

    protected CppStdModelBase(Set<String> symbols) {
        this.symbols = symbols;
    }

    /**
     * Modeling constructor.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee function.
     */
    protected void invokeConstructor(PcodeOp pcode, Graph g, Function calleeFunc) {
    	Cell thisCell = g.getCell(pcode.getInput(1));
    	thisCell.getParent().setOnHeap(true);
    	thisCell.getParent().addLocations(
				new Location("H_" + pcode.getSeqnum().getTarget().toString(), (long) 0));
    }

    /**
     * Modeling copy constructor.
     * @param pcode the pcode.
     */
    protected void invokeCopyConstructor(PcodeOp pcode, Graph g,
            Function calleeFunc) {
        if (calleeFunc.getParameterCount() != 2) {
            DebugUtil.print("Wrong parameter for: " + calleeFunc);
            return;
        }
        Cell c1 = g.getCell(pcode.getInput(1));
		Cell c2 = g.getCell(pcode.getInput(2));
		c1.merge(c2);
    }

    /**
     * Modeling destructor
     * @param pcode the pcode.
     */
    protected void invokeDestructor(PcodeOp pcode, Graph g, Function calleeFunc) {
    	Cell c1 = g.getCell(pcode.getInput(1));
    	c1.getParent().getLocations();// TODO: becomes invalid
    }

    /**
     * Invoke the function model.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee Function.
     */
    public abstract Cell invoke(PcodeOp pcode, Graph g, Function calleeFunc);


    /**
     * Add default signature.
     * @param functionName the function name.
     * @param params a list of parameters.
     * @param returnType the return type.
     */
    public void addDefaultSignature(String functionName, List<ParameterDefinitionImpl> params, DataType returnType) {
        //FIXME: Handle polymorphism signature
        Signature signature = new Signature(params, returnType);
        signatureHashMap.put(functionName, signature);
    }

    /**
     * @hidden
     * Only use in PcodeVisitor.
     * @param callee the callee function.
     */
    public void defineDefaultSignature(Function callee) {
        Signature signature = signatureHashMap.get(callee.getName());
        if (signature == null || signature.defaultParameters.size() == callee.getParameterCount()) {
            return;
        }
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define signature");
            FunctionDefinitionDataType funcSignature = new FunctionDefinitionDataType(callee.getName());
            funcSignature.setArguments(signature.defaultParameters.toArray(new ParameterDefinition[0]));
            funcSignature.setReturnType(signature.returnType);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    callee.getEntryPoint(),
                    funcSignature,
                    SourceType.USER_DEFINED
            );
            cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
            GlobalState.currentProgram.endTransaction(tid, true);
        } catch (Exception e) {
            DebugUtil.print("Fail to define signature for " + callee);
            e.printStackTrace();
        }
    }

    public Set<String> getSymbols() {
        return symbols;
    }
}
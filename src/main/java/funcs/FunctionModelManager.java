package funcs;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import bindsa.DebugUtil;
import funcs.libcfuncs.CallocFunction;
import funcs.libcfuncs.ExternalFunctionBase;
import funcs.libcfuncs.FreeFunction;
import funcs.libcfuncs.MallocFunction;
import funcs.libcfuncs.MemcpyFunction;
import funcs.libcfuncs.ReallocFunction;
import funcs.libcfuncs.StrcatFunction;
import funcs.stdfuncs.CppStdModelBase;
import funcs.stdfuncs.ListModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

public class FunctionModelManager {
	private static final List<ExternalFunctionBase> EXTERNAL_FUNCTION_LIST = List.of(
//            new LibcStartMainFunction(),
//            new TopResultFunction(),
            // Heap function
            new MallocFunction(),
            new CallocFunction(),
            new ReallocFunction(),
            new FreeFunction(),
//            new MallocUsableSizeFunction(),
            // String function
            new StrcatFunction(),
//            new StrlenFunction(),
//            new StrcpyFunction(),
//            new StrncpyFunction(),
            // Taint source functions
//            new GetcFunction(),
//            new FgetcFunction(),
//            new GetsFunction(),
//            new FgetsFunction(),
//            new ReadFunction(),
//            new RecvFunction(),
//            new GetenvFunction(),
//            new RandFunction(),
            // Taint source functions with varargs
//            new ScanfFunction(),
//            new SscanfFunction(),
//            new FscanfFunction(),
//            new StrchrFunction(),
            // varargs functions
//            new PrintfFunction(),
//            new SnprintfFunction(),
//            new FprintfFunction(),
//            new SprintfFunction(),
            // stdlib
            new MemcpyFunction()
//            new AtoiFunction(),
//            new PutsFunction()
    );

    private static List<String> stdNameSpaceStringList = List.of("std");
    private static final List<CppStdModelBase> STD_MODEL_LIST = List.of(
            new ListModel()
//            new MapModel(),
//            new VectorModel()
    );

    private static final Pattern STL_MODEL_NAME_PATTERN = Pattern.compile("(\\w+)<.*allocator.*>");
    private static final Map<String, ExternalFunctionBase> symbol2ExternalFunctionMap = new HashMap<>();
    private static final Map<Address, String> address2SymbolConfigMap = new HashMap<>();
    private static final Map<String, CppStdModelBase> symbol2StdModelMap = new HashMap<>();


    private static void initSymbol2ExternalFunctionMap() {
        for (ExternalFunctionBase functionModel : EXTERNAL_FUNCTION_LIST) {
            for (String symbol : functionModel.getSymbols()) {
                if (symbol2ExternalFunctionMap.put(symbol, functionModel) != null) {
                    DebugUtil.print("\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    private static void initSymbol2StdModelMap() {
        for (CppStdModelBase stdModel: STD_MODEL_LIST) {
            for (Object symbol: stdModel.getSymbols()) {
                if (symbol2StdModelMap.put((String) symbol, stdModel) != null) {
                    DebugUtil.print("C++ std::\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    /**
     * Checks if a function is from C++ std library.
     * @param function the function.
     * @return true if it is from C++ std library, false otherwise.
     */
    public static boolean isStd(Function function) {
        Namespace namespace = function.getParentNamespace();
        if (namespace == null) {
            return false;
        }
        String namespaceString = namespace.getName(true);
        if (namespaceString == null) {
            return false;
        }
        for (String s : stdNameSpaceStringList) {
            if (namespaceString.startsWith(s)) {
                return true;
            }
        }
        return false;
    }

    /** Get registered external function model.
    * @param symbol the symbol string.
    * @return the external function model or null if not registered.
    */
    public static ExternalFunctionBase getExternalFunction(String symbol) {
        return symbol2ExternalFunctionMap.get(symbol);
    }

    /**
     * Register a mapping from address to symbol.
     * @param address the address.
     * @param symbol the symbol string.
     * @return the old symbol if address already registered, otherwise null.
     */
    public static String mapAddress2Symbol(Address address, String symbol) {
        return address2SymbolConfigMap.put(address, symbol);
    }

    /**
     * Checks if the function entry address is mapped to a symbol.
     * @param entryAddress the function entry address.
     * @return true if the address is mapped, otherwise false.
     */
    public static boolean isFunctionAddressMapped(Address entryAddress) {
        return address2SymbolConfigMap.containsKey(entryAddress);
    }

    /**
     * Reset the address to symbol mapping.
     */
    public static void resetConfig() {
        address2SymbolConfigMap.clear();
    }

    /**
     * Get the std model.
     * @param nameSpaceString the std name space string.
     * @return the std model.
     */
    public static CppStdModelBase getStdModel(String nameSpaceString) {
        String modelName;
        Matcher matcher = STL_MODEL_NAME_PATTERN.matcher(nameSpaceString);
        if (matcher.find()) {
            modelName = matcher.group(1);
            DebugUtil.print("Match \"" + nameSpaceString + "\" to model name: " + modelName);
        } else {
            return null;
        }
        return modelName == null ? null : symbol2StdModelMap.get(modelName);
    }

    /**
     * Reset all the containers in registered std models.
     */
    public static void resetStdContainers() {
        
    }

    /**
     * Initialize all registered function models.
     */
    public static void initAll() {
        initSymbol2ExternalFunctionMap();
        initSymbol2StdModelMap();
    }
}



import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import bindsa.CallSiteNode;
import bindsa.Cell;
import bindsa.DSNode;
import bindsa.DebugUtil;
import bindsa.GlobalRegion;
import bindsa.GlobalState;
import bindsa.Graph;
import bindsa.Pair;
import funcs.FunctionModelManager;
import funcs.stdfuncs.CppStdModelBase;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class IndirectCallTargetResolving extends GhidraScript {
	private int nextId = 0;
	Address textBegin;
	Address textEnd;
	private HashMap<Function, Graph> allLocalGraphs = new HashMap<Function, Graph>();
	private HashMap<Function, Graph> allBUGraphs = new HashMap<Function, Graph>();
//	private HashMap<Address, Cell> allGlobals = new HashMap<Address, Cell>();
	private GlobalRegion globalRegion;
	private ArrayList<HashSet<Function>> sccs = new ArrayList<HashSet<Function>>();
	private HashMap<Address, HashSet<Cell>> allMemAccessInstrMap = new HashMap<Address, HashSet<Cell>>();
	public HashSet<Address> indirectCallSiteAddrs = new HashSet<Address>();
	public JSONArray nodes = new JSONArray();
	public JSONArray edges = new JSONArray();
	HashMap<String, JSONObject> funcMap = new HashMap<String, JSONObject>();
	HashMap<DSNode, JSONObject> dsnodeMap = new HashMap<DSNode, JSONObject>();
	private boolean singleEntry = false;
	private boolean propagateTaint = false;

	public JSONObject getFuncJSON(Function f) {
		/*
		 * { "key": "__cxa_finalize_thunk", "attributes": { "label":
		 * "__cxa_finalize_thunk", "modularity_class": 1, "MemoryObject": "null",
		 * "Offset": "null" } }
		 */
		JSONObject funcObj = new JSONObject();
		funcObj.put("key", f.toString());
		JSONObject attr = new JSONObject();
		attr.put("label", f.toString());
		attr.put("modularity_class", "1");
		attr.put("MemoryObject", "null");
		attr.put("Offset", "null");
		funcObj.put("attributes", attr);
		return funcObj;
	}

	public String addDSNodeJSON(DSNode ds, String label) {
		if (dsnodeMap.containsKey(ds))
			return (String) dsnodeMap.get(ds).get("key");
		JSONObject funcObj = new JSONObject();
		funcObj.put("key", label + "@offset0");
		JSONObject attr = new JSONObject();
		attr.put("label", label + "@offset0");
		attr.put("modularity_class", "1");
		attr.put("MemoryObject", label);
		attr.put("Offset", "0");
		funcObj.put("attributes", attr);
		dsnodeMap.put(ds, funcObj);
		nodes.add(funcObj);
		return (String) funcObj.get("key");
	}

	public void callGraphToJSON() {
		JSONObject callgraph = new JSONObject();
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);

		for (Function func : functionManager) {
			if (funcMap.get(func.toString()) == null) {
				funcMap.put(func.toString(), getFuncJSON(func));
				nodes.add(funcMap.get(func.toString()));
			}
			for (Function callee : func.getCalledFunctions(monitor)) {
				if (funcMap.get(callee.toString()) == null) {
					funcMap.put(callee.toString(), getFuncJSON(callee));
					nodes.add(funcMap.get(callee.toString()));
				}

				/*
				 * { "key": "0", "source": "_init", "target": "__gmon_start___thunk",
				 * "attributes": { "weight": 1.0 } }
				 */
				JSONObject edgeObj = new JSONObject();
				edgeObj.put("key", String.valueOf(edges.size()));
				edgeObj.put("source", func.toString());
				edgeObj.put("target", callee.toString());
				edges.add(edgeObj);
			}
		}
		functionManager = this.currentProgram.getFunctionManager().getFunctions(true);

		for (Function func : functionManager) {
			Graph g = allBUGraphs.get(func);
			if (g == null)
				continue;
			for (int offset : g.getStackObjPtr().keySet()) {
				DSNode obj = g.getStackObjPtr().get(offset);
				HashSet<Function> r = obj.getAllReadFunc();
				HashSet<Function> w = obj.getAllWriteFunc();
				if (r.size() > 1 || w.size() > 1) {
					String key = addDSNodeJSON(obj,
							"MemoryObject_" + func.getName() + "_Stackoffset" + String.valueOf(offset));
					for (Function f : r) {
						JSONObject edgeObj = new JSONObject();
						edgeObj.put("key", String.valueOf(edges.size()));
						edgeObj.put("source", key);
						edgeObj.put("target", f.toString());
						edges.add(edgeObj);
					}

					for (Function f : w) {
						JSONObject edgeObj = new JSONObject();
						edgeObj.put("key", String.valueOf(edges.size()));
						edgeObj.put("source", f.toString());
						edgeObj.put("target", key);
						edges.add(edgeObj);
					}
				}
			}
		}

		for (Address addr : globalRegion.getGlobalPtr().keySet()) {
			Cell c = globalRegion.getGlobalPtr().get(addr);
			DSNode obj = c.getParent();
			if (dsnodeMap.containsKey(obj))
				continue;
			HashSet<Function> r = obj.getAllReadFunc();
			HashSet<Function> w = obj.getAllWriteFunc();
			if (r.size() > 1 || w.size() > 1) {
				String key = addDSNodeJSON(obj, "MemoryObject_Global_" + addr.toString());
				for (Function f : r) {
					JSONObject edgeObj = new JSONObject();
					edgeObj.put("key", String.valueOf(edges.size()));
					edgeObj.put("source", key);
					edgeObj.put("target", f.toString());
					edges.add(edgeObj);
				}
				for (Function f : w) {
					JSONObject edgeObj = new JSONObject();
					edgeObj.put("key", String.valueOf(edges.size()));
					edgeObj.put("source", f.toString());
					edgeObj.put("target", key);
					edges.add(edgeObj);
				}
			}
		}
		callgraph.put("nodes", nodes);
		callgraph.put("links", edges);

		try {
			Files.write(Paths.get(GlobalState.decompiledPath + currentProgram.getName() + ".json"),
					callgraph.toJSONString().getBytes());
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

	/*
	 * set up the decompiler
	 */
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();
		DecompileOptions options;
		options = new DecompileOptions();
//		PluginTool tool = state.getTool();
//		if (tool != null) {
//			OptionsService service = tool.getService(OptionsService.class);
//			if (service != null) {
//				ToolOptions opt = service.getOptions("Decompiler");
//				options.grabFromToolAndProgram(null, opt, program);
//			}
//		}
		decompInterface.setOptions(options);
		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	private DecompileResults decompileFunction(Function f) {
		DecompileResults dRes = null;

		try {
			dRes = GlobalState.decomplib.decompileFunction(f, GlobalState.decomplib.getOptions().getDefaultTimeout(), getMonitor());
//			DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(dRes);
//			cmd.applyTo(currentProgram);
		} catch (Exception exc) {
			DebugUtil.print("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return dRes;
	}

	public HashMap<PcodeOp, ArrayList<ClangToken>> mapPcodeOpToClangTokenList(ClangTokenGroup ccode) {
		List<ClangNode> lst = new ArrayList<ClangNode>();
		ccode.flatten(lst);
		ArrayList<ClangLine> lines = DecompilerUtils.toLines(ccode);
		HashMap<PcodeOp, ArrayList<ClangToken>> mapping = new HashMap<PcodeOp, ArrayList<ClangToken>>();

		for (ClangLine l : lines) {
//			println(l.toString());
			for (ClangToken c : l.getAllTokens()) {
				if (c.getPcodeOp() != null) {
//					println("--- " + c.toString() + " " + c.getPcodeOp().toString() + " " + c.getPcodeOp().getSeqnum().toString());
					if (!mapping.containsKey(c.getPcodeOp())) {
						mapping.put(c.getPcodeOp(), new ArrayList<ClangToken>());
					}
					mapping.get(c.getPcodeOp()).add(c);
				}
			}
		}
		return mapping;
	}

	public void export(ClangTokenGroup ccode, Function f) {
		try {
			String name;
			if (f.isThunk())
				name = f.getName() + "_thunk";
			else
				name = f.getName();

			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(GlobalState.decompiledPath + name + ".c")));
			ArrayList<ClangLine> lines = DecompilerUtils.toLines(ccode);
			for (ClangLine l : lines) {
				out.write(l.toString());
				out.newLine();
			}
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void analyzeLocalFuncs(Function f) {
		try {
			if (f.toString().equals("default_bzalloc")) {
				DataType dt = currentProgram.getDataTypeManager().getDataType("bzip2/void *");
				f.setReturnType(dt, SourceType.ANALYSIS);
			}
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		DecompileResults dRes = decompileFunction(f);
		HighFunction hfunction = dRes.getHighFunction();
		if (hfunction == null)
			return;

		Graph localGraph = new Graph();
		allLocalGraphs.put(f, localGraph);
		localGraph.setF(f);
		localGraph.setAllGlobals(globalRegion);
		localGraph.setAllLocalGraphs(allLocalGraphs);
		localGraph.setMemAccessInstrMap(allMemAccessInstrMap);

		ClangTokenGroup ccode = dRes.getCCodeMarkup();
		HashMap<PcodeOp, ArrayList<ClangToken>> mapping = mapPcodeOpToClangTokenList(ccode);
		localGraph.setMapping(mapping);
		export(ccode, f);

		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();

		if (bb.size() == 0)
			return;

		Boolean[] visited = new Boolean[bb.size()];
		Arrays.fill(visited, Boolean.FALSE);

		Queue<PcodeBlockBasic> workList = new LinkedList<>();
		workList.addAll(bb);
		for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); i++) {
			if (hfunction.getFunctionPrototype().getParam(i).getHighVariable() == null)
				continue;
			Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
			localGraph.addArg(key, "ARG" + String.valueOf(i + 1));
		}

		int it = 0;
		Varnode targetNode = null;
		while (!workList.isEmpty() && !monitor.isCancelled()) {
			boolean stateChanged = false;
			PcodeBlockBasic pBB = workList.remove();
//			System.out.println("start at " + pBB.getStart() + " end at " + pBB.getStop());
			Iterator<PcodeOp> opIter = pBB.getIterator();
			it++;
			if (it / bb.size() > 4) {
				// this is for debugging
				DebugUtil.print("dead loop!!!");
				break;
			} else if (it / bb.size() > 4) {
				// this is for debugging
				DebugUtil.print("dead loop!!!");
				break;
			}

//			println(pBB.toString());
			while (opIter.hasNext()) {
				PcodeOp pcodeOp = opIter.next();
//				if (toString(pcodeOp.getInput(0), currentProgram.getLanguage()).contains("u_7a80:4_90")
//						&& targetNode == null)
//					targetNode = pcodeOp.getInput(0);
				boolean changed = analyzePcodeOp(pcodeOp, localGraph);
				stateChanged = stateChanged || changed;
//				if (targetNode != null) {
//					Cell targetCell = localGraph.getCell(targetNode);
//					if (targetCell.getParent().members.containsKey(-7)
//							|| targetCell.getParent().members.containsKey(-1)) {
//						System.out.print("");
//					}
//					if (targetCell.getPossiblePointers().size() > 0) {
//						System.out.print("");
//					}
//				}
			}

			if (stateChanged) {
				int neighbours = pBB.getOutSize();
				for (int i = 0; i < neighbours; i++) {
					if (!workList.contains(pBB.getOut(i)))
						workList.add((PcodeBlockBasic) pBB.getOut(i));
				}
			}
		}
		localGraph.setMapping(null);

		DebugUtil.print("Used memory "
				+ String.valueOf(Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()));
		DebugUtil.print("Free memory" + String.valueOf(Runtime.getRuntime().freeMemory()));
		DebugUtil.print("node size: " + localGraph.getEv().size());

//		if (!f.getName().toString().contains("select_file_type"))
//			localGraph.getReturnCell();
	}

	public int parseInt(String symbol) {
		int ret;
		if (symbol == "VZERO") {
			ret = 0;
		} else if (symbol.startsWith("0x")) {
			ret = new BigInteger(symbol.substring(2), 16).intValue();
		} else {
			ret = new BigInteger(symbol, 10).intValue();
		}

		return ret;
	}

	public Address getPossiblePointer(PcodeOp pcodeOp) {
		PcodeOp def = pcodeOp.getInput(2).getDef();
		if (def != null && def.getOpcode() == PcodeOp.PTRSUB) {
			Address offset = def.getInput(1).getAddress();

//			fp = this.currentProgram.getFunctionManager().getFunctionAt(offset);
			if (offset.isMemoryAddress())
				return offset;
			Address memAddr = currentProgram.getAddressFactory().getAddress(
					currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(), offset.getOffset());
			if (memAddr == null)
				return null;
			Instruction instr = currentProgram.getListing().getInstructionAt(memAddr);
			if (instr != null)
				return memAddr;
		}
		return null;
	}

	public static HashSet<Address> getPossibleFuncPointer(HashSet<Address> allpointers, Program curProgram) {
		HashSet<Address> fps = new HashSet<Address>();
		for (Address p : allpointers) {
			Address memAddr = isFuncPointer(p, curProgram);
			if (memAddr != null)
				fps.add(memAddr);
		}
		return fps;
	}

	public static Address isFuncPointer(Address p, Program curProgram) {
		Address memAddr = curProgram.getAddressFactory()
				.getAddress(curProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(), p.getOffset());
		Function fp = curProgram.getFunctionManager().getFunctionAt(memAddr);
		if (fp != null) {
			GlobalState.targetFuncSuperSet.add(fp);
			return memAddr;
		}
		return null;
	}

	public boolean isSmallConstants(long offset) {
		if (0 < offset && offset < currentProgram.getDefaultPointerSize())
			return true;
		if (0 > offset && offset > -currentProgram.getDefaultPointerSize())
			return true;
		return false;
	}

	

	public boolean analyzePcodeOp(PcodeOp pcodeOp, Graph graph) {
		String outStr = toString(pcodeOp, currentProgram.getLanguage()) + " " + pcodeOp.getSeqnum().toString();
		DebugUtil.print(outStr);
		graph.changed = false;
		switch (pcodeOp.getOpcode()) {
		case PcodeOp.UNIMPLEMENTED:
			break;
		case PcodeOp.CAST:
		case PcodeOp.INDIRECT:
			// input0 is copied to output, but the value may be altered in an indirect way
			// by the operation referred to by input1
			// so need to view it as copy. And the stack value need to be updated if shown
			// in the output
			if (pcodeOp.getOutput() == pcodeOp.getInput(0))
				break;
		case PcodeOp.INT_ZEXT:
		case PcodeOp.INT_SEXT:
		case PcodeOp.COPY:
			Pair<Varnode, Integer> newVarRelation = new Pair<Varnode, Integer>(pcodeOp.getInput(0), 0);
			graph.setRelation(pcodeOp.getOutput(), newVarRelation);
			Cell c1 = graph.getCell(pcodeOp.getInput(0));
			Cell c2 = graph.getCell(pcodeOp.getOutput());
			if (propagateTaint && c2.hasTaintedInEdge())
				System.err.println("Vul found at offset " + pcodeOp.getSeqnum().getTarget().toString() + " in "
						+ currentProgram.getExecutablePath());

//			if (c2 != null && c2.getParent() != null && c2.getParent().isGlobal())
//				c2.merge(c1);
			break;
		case PcodeOp.LOAD:
			Cell mem = graph.getCell(pcodeOp.getInput(1));
			Cell out = null;
			if (mem.getOutEdges() != null) {
				out = mem.getOutEdges();
				out.addInEvEdges(pcodeOp.getOutput());
				graph.setEv(pcodeOp.getOutput(), out);
			} else {
				out = graph.getCell(pcodeOp.getOutput());
				mem.addOutEdges(out);
			}
			mem = graph.getCell(pcodeOp.getInput(1));
			mem.setReadFunc(graph.getF());
			mem.addMemAccessInstr(pcodeOp.getSeqnum().getTarget());
			graph.addMemAccessInstrMap(pcodeOp.getSeqnum().getTarget(), mem);
			break;
		case PcodeOp.STORE:
			mem = graph.getCell(pcodeOp.getInput(1));
			if (propagateTaint && mem.isTainted())
				System.err.println("Vul found at offset " + pcodeOp.getSeqnum().getTarget().toString() + " in "
						+ currentProgram.getExecutablePath());
//			else if (propagateTaint && mem.getParent().isGlobal() && mem.getWriteFunc().size() == 0)
//				System.err.print("Vul found at offset " + pcodeOp.getSeqnum().getTarget().toString());

			mem.setWriteFunc(graph.getF());
			mem.addMemAccessInstr(pcodeOp.getSeqnum().getTarget());
			graph.addMemAccessInstrMap(pcodeOp.getSeqnum().getTarget(), mem);
			Cell val = graph.getCell(pcodeOp.getInput(2));
			mem.addOutEdges(val);

			break;
		case PcodeOp.BRANCH:
			break;
		case PcodeOp.CBRANCH:
//			String cond = mstate.getVnodeValue(pcodeOp.getInput(1), true).toString();
//			mstate.addConditions(pcodeOp.getSeqnum(), cond);
			break;
		case PcodeOp.BRANCHIND:
			break;
		case PcodeOp.CALL:
			Address addr = pcodeOp.getInput(0).getAddress();
			Function fp = this.currentProgram.getFunctionManager().getFunctionAt(addr);
			if (fp != null && (fp.getName().equals("<EXTERNAL>::malloc") || fp.getName().equals("<EXTERNAL>::calloc")||fp.getName().equals("malloc") || fp.getName().equals("calloc") || fp.getName().equals("<EXTERNAL>::operator.new")|| fp.getName().equals("operator.new"))
					&& pcodeOp.getOutput() != null) {
				out = graph.getCell(pcodeOp.getOutput());
				if (fp.getName().contains("malloc") && pcodeOp.getInput(1) != null && pcodeOp.getInput(1).isConstant()) {
					out.getParent().setSize((int) pcodeOp.getInput(1).getOffset());
				}
				if (fp.getName().contains("calloc") && pcodeOp.getInput(1) != null && pcodeOp.getInput(1).isConstant() && pcodeOp.getInput(2) != null && pcodeOp.getInput(2).isConstant()) {
					out.getParent().setSize((int) pcodeOp.getInput(1).getOffset() * (int) pcodeOp.getInput(2).getOffset());
				}
				out.getParent().setOnHeap(true);
				out.getParent().addLocations(
						new Pair<String, Long>("H_" + pcodeOp.getSeqnum().getTarget().toString(), (long) 0));
				break;
			}
			if (fp != null && fp.getName().contains("memcpy") && pcodeOp.getInputs().length >= 3) {
				c1 = graph.getCell(pcodeOp.getInput(1));
				c2 = graph.getCell(pcodeOp.getInput(2));
				c1.merge(c2);
				break;
			}
			if (FunctionModelManager.isStd(fp)) {
				String namespaceString = fp.getParentNamespace().getName();
		        CppStdModelBase stdModel = FunctionModelManager.getStdModel(namespaceString);
		        if (stdModel != null) {
		        	stdModel.defineDefaultSignature(fp);
		        	Cell funcout = stdModel.invoke(pcodeOp, graph, fp);
		        	if (funcout != null && pcodeOp.getOutput() != null)
		        		graph.setEv(pcodeOp.getOutput(), funcout);
		        }
		        break;
			}
			ArrayList<Cell> callargs = new ArrayList<Cell>();
			for (int i = 1; i < pcodeOp.getNumInputs(); ++i) {
				Cell argCell = graph.getCell(pcodeOp.getInput(i));
				// for Mirai
//				if (pcodeOp.getSeqnum().getTarget().toString().contains("4072e1") && i == 2) {
//					arg = graph.getCell(pcodeOp.getInput(i));
//					arg.getParent().setTainted(true);
//				} else
				
				// for NPD
				Varnode arg = pcodeOp.getInput(i);
				if (arg.getHigh().getDataType().equals(PointerDataType.dataType)) {
					argCell.addMemAccessInstr(pcodeOp.getSeqnum().getTarget());
					graph.addMemAccessInstrMap(pcodeOp.getSeqnum().getTarget(), argCell);
				}
				callargs.add(argCell);
			}
			Cell func = graph.getCell(pcodeOp.getInput(0));
			func.addPointers(addr);
			Cell ret = graph.getCell(pcodeOp.getOutput());
			CallSiteNode oldCSite = graph.getCallNodes(pcodeOp.getSeqnum().getTarget());
			if (oldCSite != null) {
				oldCSite.update(ret, func, callargs);
			} else {
				CallSiteNode csite = new CallSiteNode(ret, func, callargs, pcodeOp.getSeqnum().getTarget(), graph);
				graph.addCallNodes(pcodeOp.getSeqnum().getTarget(), csite);
			}
			break;
		case PcodeOp.CALLIND:
			callargs = new ArrayList<Cell>();
			for (int i = 1; i < pcodeOp.getNumInputs(); ++i) {
				Cell arg = graph.getCell(pcodeOp.getInput(i));
				callargs.add(arg);
			}
			// taint ReadSaveState arg
			if (pcodeOp.getInput(0).getHigh().getDataType().getName().equals("EFI_SMM_READ_SAVE_STATE")) {
				callargs.get(4).getParent().setTainted(true);
			}

			func = graph.getCell(pcodeOp.getInput(0));
			graph.hasIndirectCallee = true;
			if (propagateTaint && func.isTainted())
				System.err.println("Vul found at offset " + pcodeOp.getSeqnum().getTarget().toString() + " in "
						+ currentProgram.getExecutablePath());
//			else if (propagateTaint && func.getParent().isGlobal() && func.getWriteFunc().size() == 0)
//				System.err.print("Vul found at offset " + pcodeOp.getSeqnum().getTarget().toString());

			// this address could be resolved within current function
			int count = 0;
			String fpstr = "";
			HashSet<Address> addrs = new HashSet<Address>();
			addrs.addAll(func.getPossiblePointers());
			for (Address funcAddr : addrs) {
				if (!funcAddr.isMemoryAddress())
					funcAddr = currentProgram.getAddressFactory().getAddress(
							currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
							funcAddr.getOffset());

				fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);

				if (fp != null) {
					count += 1;
					fpstr += fp.getName() + ", ";
					Instruction instr = currentProgram.getListing().getInstructionAt(pcodeOp.getSeqnum().getTarget());
					if (instr == null)
						continue;
					instr.addOperandReference(0, funcAddr, RefType.COMPUTED_CALL, SourceType.USER_DEFINED);
				} else {
					func.getPossiblePointers().remove(funcAddr);
				}
			}

			ret = graph.getCell(pcodeOp.getOutput());
			oldCSite = graph.getCallNodes(pcodeOp.getSeqnum().getTarget());
			if (oldCSite != null) {
				oldCSite.update(ret, func, callargs);
			} else {
				CallSiteNode csite = new CallSiteNode(ret, func, callargs, pcodeOp.getSeqnum().getTarget(), graph);
				csite.isIndirect = true;
				csite.numIndirectCall = 1;
				if (pcodeOp.getInput(0).getAddress().isMemoryAddress())
					csite.isGlobalAddr = true;
				graph.addCallNodes(pcodeOp.getSeqnum().getTarget(), csite);
				String tokens = graph.getMapping().get(pcodeOp).get(0).getLineParent().toString();
				csite.setTokens(tokens);
				BufferedWriter outf;
				try {
					outf = new BufferedWriter(
							new OutputStreamWriter(new FileOutputStream(GlobalState.targetPath, true)));
					outf.write(pcodeOp.getSeqnum().getTarget().toString() + "@" + tokens);
					outf.newLine();
					outf.close();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				if (count > 0) {
					try {
						outf = new BufferedWriter(new OutputStreamWriter(
								new FileOutputStream(GlobalState.outPath, true)));
						outf.write(csite.toString() + "@" + String.valueOf(count) + "@" + fpstr);
						outf.newLine();
						outf.close();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}

			break;
		case PcodeOp.CALLOTHER:
			break;
		case PcodeOp.RETURN:
			graph.getCell(pcodeOp.getInput(1));
			graph.addRet(pcodeOp.getInput(1));
			break;
		case PcodeOp.FLOAT_EQUAL:
		case PcodeOp.FLOAT_NOTEQUAL:
		case PcodeOp.FLOAT_LESS:
		case PcodeOp.FLOAT_LESSEQUAL:
		case PcodeOp.INT_EQUAL:
		case PcodeOp.INT_NOTEQUAL:
		case PcodeOp.INT_SLESS:
		case PcodeOp.INT_SLESSEQUAL:
		case PcodeOp.INT_LESS:
		case PcodeOp.INT_LESSEQUAL:
			break;
		case PcodeOp.PTRSUB:
			if (pcodeOp.getInput(0).isConstant() && pcodeOp.getInput(0).getOffset() == 0) {
				Address offset = pcodeOp.getInput(1).getAddress();
				Address memAddr = currentProgram.getAddressFactory().getAddress(
						currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(), offset.getOffset());
				if (memAddr != null && (currentProgram.getListing().getDataAt(memAddr) != null
						|| isFuncPointer(memAddr, currentProgram) != null)) {
					Cell outCell = graph.getCell(pcodeOp.getOutput());
					outCell.addPointersWithLoading(memAddr);
					if (isFuncPointer(memAddr, currentProgram) != null) {
						outCell.getGraph().hasFuncPtr = true;
						DebugUtil.print(
								outCell.getGraph().getF().toString() + " assign func pointer " + memAddr.toString());
					}
					break;
				}
			}
		case PcodeOp.FLOAT_ADD:
		case PcodeOp.INT_CARRY:
		case PcodeOp.INT_SCARRY:
		case PcodeOp.INT_ADD:
			Varnode vnode1 = pcodeOp.getInput(0);
			Varnode vnode2 = pcodeOp.getInput(1);
			Varnode onode = pcodeOp.getOutput();
			Cell cell1 = graph.getCell(vnode1);
			Cell cell2 = graph.getCell(vnode2);

			// if cell1 and cell2 stores normal constants, calculate them
			if (!cell1.getParent().isCollapsed() && !cell2.getParent().isCollapsed()
					&& cell1.getParent().getConstants() != null && cell2.getParent().getConstants() != null) {
				int offset1 = cell1.getParent().getConstants();
				int offset2 = cell2.getParent().getConstants();
				Cell outCell = graph.getCell(onode);
				outCell.getParent().addConstants(offset1 + offset2);
				break;
			}

			if (vnode1.isConstant()) {
				int offset = parseInt(vnode1.toString(currentProgram.getLanguage()));
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode2, offset));
				if (isSmallConstants(vnode1.getOffset())) {
					Cell outCell = graph.getCell(onode);
					outCell.getParent().setIsConstant(true);
					cell2 = graph.getCell(vnode2);
					cell2.getParent().setIsConstant(true);
				}
			} else if (vnode2.isConstant()) {
				int offset = parseInt(vnode2.toString(currentProgram.getLanguage()));
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, offset));
				if (isSmallConstants(vnode2.getOffset())) {
					Cell outCell = graph.getCell(onode);
					outCell.getParent().setIsConstant(true);
					cell1 = graph.getCell(vnode1);
					cell1.getParent().setIsConstant(true);
				}
			} else if (cell1.getParent().isCollapsed() && cell1.getParent().getConstants() == null) { 
				// cell1 is collapsed but not storing constants
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, 0));
			} else if (cell2.getParent().isCollapsed() && cell2.getParent().getConstants() == null) {
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode2, 0));
			} else if (cell1.getParent().getConstants() != null) {
				// one of the value is known
				int offset = cell1.getParent().getConstants();
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode2, offset));
			} else if (cell2.getParent().getConstants() != null) {
				int offset = cell2.getParent().getConstants();
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, offset));
			} else if (cell2.getParent().getIsConstant() && cell2.getParent().isCollapsed() && cell1.getGlobalAddrs().size() > 0) {
				// perform collapse for global arrays if + T
//				cell1.getParent().collapse(false);
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, 0));
				graph.getCell(onode).getParent().setArray(true);
			} else if (cell1.getParent().getIsConstant() && cell1.getParent().isCollapsed() && cell2.getGlobalAddrs().size() > 0) {
//				cell2.getParent().collapse(false);
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode2, 0));
				graph.getCell(onode).getParent().setArray(true);
			} else if (cell1.getParent().getIsConstant() && cell2.getParent().getIsConstant()) {
				// cell1 and cell2 are both values (with value unknown)
				Cell outCell = graph.getCell(onode);
				outCell.getParent().setIsConstant(true);
			} else if (cell2.getParent().hasStride() || cell1.getParent().isArray()) {
				// if value is unknown, but it is a index of array, track at offset 0
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, 0));
				Cell outCell = graph.getCell(onode);
				outCell.getParent().setArray(true);
				outCell.getParent().setPossibleStride(cell2.getParent().getPossibleStride());
			} else if (cell1.getParent().hasStride() || cell2.getParent().isArray()) {
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode2, 0));
				Cell outCell = graph.getCell(onode);
				outCell.getParent().setArray(true);
				outCell.getParent().setPossibleStride(cell1.getParent().getPossibleStride());
//	
			}
			// TODO: other cases, the points-to relations are lost
			break;
		case PcodeOp.FLOAT_SUB:
		case PcodeOp.INT_SBORROW:
		case PcodeOp.INT_SUB:
			vnode1 = pcodeOp.getInput(0);
			vnode2 = pcodeOp.getInput(1);
			onode = pcodeOp.getOutput();
			cell2 = graph.getCell(vnode2);
			cell1 = graph.getCell(vnode1);
			if (cell1.getParent().getConstants() != null && cell2.getParent().getConstants() != null) {
				int offset1 = cell1.getParent().getConstants();
				int offset2 = cell2.getParent().getConstants();
				Cell outCell = graph.getCell(onode);
				outCell.getParent().addConstants(offset1 - offset2);
				break;
			}

			if (cell1.getParent().isCollapsed() && cell1.getParent().getConstants() == null) {
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, 0));
			} else if (cell2.getParent().getConstants() != null) {
				int offset = cell2.getParent().getConstants();
				if (offset == GlobalState.TOP)
					graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, GlobalState.TOP));
				else
					graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, -offset));
				if (isSmallConstants(offset)) {
					Cell outCell = graph.getCell(onode);
					outCell.getParent().setIsConstant(true);
					cell1.getParent().setIsConstant(true);
				}
				graph.getCell(vnode1);
			}
			break;
		case PcodeOp.PIECE:
		case PcodeOp.BOOL_AND:
		case PcodeOp.BOOL_OR:
			vnode1 = pcodeOp.getInput(0);
			vnode2 = pcodeOp.getInput(1);
			onode = pcodeOp.getOutput();
			cell1 = graph.getCell(vnode1);
			cell1.getParent().setIsConstant(true);
			cell2 = graph.getCell(vnode2);
			cell2.getParent().setIsConstant(true);
			Cell outCell = graph.getCell(onode);
			outCell.getParent().setIsConstant(true);
			break;
		case PcodeOp.SUBPIECE:
			break;
		case PcodeOp.BOOL_NEGATE:
		case PcodeOp.INT_NEGATE:
		case PcodeOp.INT_2COMP:
		case PcodeOp.FLOAT_NEG:
		case PcodeOp.FLOAT_NAN:
		case PcodeOp.FLOAT_ABS:
		case PcodeOp.FLOAT_SQRT:
		case PcodeOp.FLOAT_INT2FLOAT:
		case PcodeOp.FLOAT_FLOAT2FLOAT:
		case PcodeOp.FLOAT_TRUNC:
		case PcodeOp.FLOAT_CEIL:
		case PcodeOp.FLOAT_FLOOR:
		case PcodeOp.FLOAT_ROUND:
			vnode1 = pcodeOp.getInput(0);
			onode = pcodeOp.getOutput();
			cell1 = graph.getCell(vnode1);
			cell1.getParent().setIsConstant(true);
			outCell = graph.getCell(onode);
			outCell.getParent().setIsConstant(true);
			if (cell1.getParent().hasStride())
				outCell.getParent().setPossibleStride(cell1.getParent().getPossibleStride());
			break;
		case PcodeOp.BOOL_XOR:
		case PcodeOp.INT_XOR:
		case PcodeOp.INT_LEFT:
		case PcodeOp.INT_RIGHT:
		case PcodeOp.INT_SRIGHT:
		case PcodeOp.INT_AND:
		case PcodeOp.INT_OR:
		case PcodeOp.INT_MULT:
		case PcodeOp.FLOAT_MULT:
		case PcodeOp.INT_DIV:
		case PcodeOp.INT_SDIV:
		case PcodeOp.FLOAT_DIV:
		case PcodeOp.INT_REM:
		case PcodeOp.INT_SREM:
			vnode1 = pcodeOp.getInput(0);
			vnode2 = pcodeOp.getInput(1);
			onode = pcodeOp.getOutput();
			cell1 = graph.getCell(vnode1);
			cell2 = graph.getCell(vnode2);
			cell1.getParent().setIsConstant(true);
			cell2.getParent().setIsConstant(true);

			// if cell1 and cell2 stores normal constants, calculate them
			if (cell1.getParent().getConstants() != null && cell2.getParent().getConstants() != null) {
				int offset1 = cell1.getParent().getConstants();
				int offset2 = cell2.getParent().getConstants();
				outCell = graph.getCell(onode);
				outCell.getParent().setIsConstant(true);
				if (cell1.getParent().isCollapsed() || cell2.getParent().isCollapsed())
					outCell.getParent().collapse(true);
				else
					outCell.getParent().addConstants(calculate(offset1, offset2, pcodeOp.getOpcode()));
			} else {
				outCell = graph.getCell(onode);
				outCell.getParent().setIsConstant(true);
				// multiplication implies a stride
				if (pcodeOp.getOpcode() == PcodeOp.INT_MULT) {
					if (cell1.getParent().getConstants() != null)
						outCell.getParent().setPossibleStride(cell1.getParent().getConstants());
					else if (cell2.getParent().getConstants() != null)
						outCell.getParent().setPossibleStride(cell2.getParent().getConstants());
				}
			}
			
			break;
		case PcodeOp.MULTIEQUAL:
//			System.out.println(pcodeOp.toString());
			// TODO: handle changes
			DSNode existNodes;
			boolean sameParent = true;
			out = graph.getCell(pcodeOp.getOutput());
			existNodes = out.getParent();
			boolean allIsConst = true;
			boolean allIsCharPtr = true;
			for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
				if (graph.getEv(pcodeOp.getInput(i)) == null) {
					out.isLoopVariant = true;
					continue;
				}
				Cell input = graph.getCell(pcodeOp.getInput(i));
				allIsConst &= input.getParent().getIsConstant();
				allIsCharPtr &= input.getParent().isCharPointer();
				if (existNodes != input.getParent())
					sameParent = false;
			}
			if (allIsConst)
				out.getParent().setIsConstant(true);
			if (allIsCharPtr)
				out.getParent().setCharPointer(true);
			
			for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
				out = graph.getCell(pcodeOp.getOutput());
				Varnode vi = pcodeOp.getInput(i);
				if (graph.getEv(vi) == null) {
					continue;
				}
				Cell input = graph.getCell(vi);
				
				// set the stride of out if possible
				if (out != null && out.isLoopVariant && sameParent && allIsConst && !out.getParent().hasStride()) {
					Integer oldValue = out.getParent().getConstants();
					Integer newValue = input.getParent().getConstants();
					if (oldValue != null && newValue != null && oldValue.intValue() != newValue.intValue()) {
						int max = newValue.intValue() > oldValue.intValue()? newValue.intValue(): oldValue.intValue();
						int min = newValue.intValue() < oldValue.intValue()? newValue.intValue(): oldValue.intValue();
						int stride = max - min;
						out.getParent().setPossibleStride(stride);
					}
				}
				if (out != null) {
					out.merge(input);
				}
			}
			
			break;
		case PcodeOp.PTRADD:
			vnode1 = pcodeOp.getInput(0);
			vnode2 = pcodeOp.getInput(1);
			Varnode vnode3 = pcodeOp.getInput(2);
			onode = pcodeOp.getOutput();
			cell2 = graph.getCell(vnode2);
			Cell cell3 = graph.getCell(vnode3);
			cell1 = graph.getCell(vnode1);
			cell2.getParent().setIsConstant(true);
			cell3.getParent().setIsConstant(true);
			if (cell2.getParent().getConstants() != null && cell3.getParent().getConstants() != null) {
				// do not set collapse here because ghidra may make mistakes identifying arrays
				int offset = cell2.getParent().getConstants();
				int offset2 = cell3.getParent().getConstants();
				if (offset == GlobalState.TOP || offset2 == GlobalState.TOP)
					graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, GlobalState.TOP));
				else
					graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, offset * offset2));
				graph.getCell(vnode1);
				if (offset * offset2 == 1) {
					outCell = graph.getCell(onode);
					outCell.getParent().setIsConstant(true);
					graph.getCell(vnode1).getParent().setIsConstant(true);
				}
			} else {
                // if one of the value is unknown, outCell is an array
				graph.setRelation(onode, new Pair<Varnode, Integer>(vnode1, 0));
				outCell = graph.getCell(onode);
				outCell.getParent().setArray(true);
				cell1.getParent().setArray(true);
			}

			if (cell3.getParent().getConstants() != null) {
				int offset2 = cell3.getParent().getConstants();
				graph.getCell(vnode1).getParent().setPossibleStride(offset2);
			}
			break;
		case PcodeOp.CPOOLREF:
		case PcodeOp.NEW:
		default:

		}
		if (graph.changed) {
//			DebugUtil.print("graph changed");
			return true;
		}
		return false;
	}

	private int calculate(int offset1, int offset2, int opcode) {
		switch (opcode) {
		case PcodeOp.BOOL_XOR:
		case PcodeOp.INT_XOR:
			return offset1 ^ offset2;
		case PcodeOp.INT_LEFT:
			return offset1 << offset2;
		case PcodeOp.INT_RIGHT:
		case PcodeOp.INT_SRIGHT:
			return offset1 >> offset2;
		case PcodeOp.INT_AND:
			return offset1 & offset2;
		case PcodeOp.INT_OR:
			return offset1 | offset2;
		case PcodeOp.INT_MULT:
		case PcodeOp.FLOAT_MULT:
			return offset1 * offset2;
		case PcodeOp.INT_DIV:
		case PcodeOp.INT_SDIV:
		case PcodeOp.FLOAT_DIV:
			if (offset2 != 0)
				return offset1 / offset2;
			return 0;
		case PcodeOp.INT_REM:
		case PcodeOp.INT_SREM:
			if (offset2 != 0)
				return offset1 % offset2;
		}
		return 0;
	}

	public void resolveCallee(Graph caller, Function callee, CallSiteNode cs) {
		Map<DSNode, DSNode> isomorphism = new IdentityHashMap<DSNode, DSNode>();
		caller.cloneGraphIntoThis(allBUGraphs.get(callee), callee, cs, isomorphism);
		Address loc = cs.getLoc();
//		caller.getCallNodes().remove(loc);
//		cs.setResolved(true);
	}

	public void resolveCallerTypes(Graph caller, Graph callee, CallSiteNode cs) {
		Function calleef = callee.getF();
		Map<DSNode, DSNode> isomorphism = new IdentityHashMap<DSNode, DSNode>();
		ArrayList<Cell> argFormal = callee.getArgCell();
		for (int i = 0; i < argFormal.size(); i++) {
			Cell arg = argFormal.get(i);
			if (arg == null)
				continue;
			DSNode argNode = arg.getParent();
			int offset = arg.getFieldOffset();

			setDataType(cs.getArgI(i), calleef.getParameter(i));

		}

		// copy and merge return node
		Cell retCell = callee.getReturnCell();
		DSNode retNode = retCell.getParent();
		int offset = retCell.getFieldOffset();
		if (retNode != null && (retNode.getOnHeap() || retNode.getIsArg() || retNode.getMembers().size() > 1)) {
			setDataType(cs.getReturn(), calleef.getReturn());
		}

	}

	public void resolveCaller(Graph caller, Function calleef, CallSiteNode cs) {
		Map<DSNode, DSNode> isomorphism = new IdentityHashMap<DSNode, DSNode>();
		Graph callee = allBUGraphs.get(calleef);
		callee.cloneCallerGraphIntoThis(caller, calleef, cs, isomorphism);
		callee.getF();
	}

	public void setDataType(Cell c, Parameter p) {
		Pointer dtype = c.getParent().getDataType(currentProgram);
		try {
			p.setDataType(dtype, SourceType.USER_DEFINED);
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void processSCC(HashSet<Function> scc, ArrayList<Function> stk, HashMap<Function, Integer> val,
			HashMap<Function, Integer> low, HashMap<Function, Boolean> inStack) {
		boolean newResolvedCallsite = false;
		int count = 0;
		for (int id : val.values()) {
			if (id != -1)
				count += 1;
		}
		System.out.printf("bottom up: %.2f\n", (float) count / val.size());
		DebugUtil.print("Process SCC: " + scc.toString());
//		if (level > 1)
//			return;
//		if (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory() > 2000000000)
//			System.gc();

		int sccsLen = sccs.size();
		if (sccsLen > 0 && scc.containsAll(sccs.get(sccsLen - 1)))
			sccs.add(sccsLen - 1, scc);
		else
			sccs.add(scc);

		// merged the callees of all functions in scc
		for (Function f : scc) {
			Graph g = allBUGraphs.get(f);
			if (g == null)
				continue;
			HashSet<CallSiteNode> clonedcs = new HashSet<CallSiteNode>();
			for (CallSiteNode cs : g.getCallNodes().values()) {
				if (!cs.getResolved() && cs.getFunc() != null && cs.getFunc().getParent() != null) {
					HashSet<Address> allAddr = new HashSet<Address>();
					allAddr.addAll(cs.getFunc().getPossiblePointers());
					for (Address funcAddr : allAddr) {
						if (!funcAddr.isMemoryAddress())
							funcAddr = currentProgram.getAddressFactory().getAddress(
									currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
									funcAddr.getOffset());
						Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
						if (fp != null && !scc.contains(fp) && allBUGraphs.get(fp) != null) {
							clonedcs.add(cs);
						}
					}
				}
			}
			for (CallSiteNode cs : clonedcs) {
				HashSet<Address> allAddr = new HashSet<Address>();
				allAddr.addAll(cs.getFunc().getPossiblePointers());
				for (Address funcAddr : allAddr) {
					if (!funcAddr.isMemoryAddress())
						funcAddr = currentProgram.getAddressFactory().getAddress(
								currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
								funcAddr.getOffset());
					Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
					Graph callee = allBUGraphs.get(fp);
					if (fp != null && !scc.contains(fp) && callee != null) {
						if ((allAddr.size() > 1 && !callee.hasFuncPtr && !callee.hasIndirectCallee)
								|| allAddr.size() > 100) {
							DebugUtil.print("skip callee " + fp.toString() + " for " + f.toString());
							continue;
						}
						resolveCallee(g, fp, cs);
						cs.addResolved(funcAddr);
						cs.setResolved(true);

					}
				}
			}
			if (g.resolvedNewCallSite) {
				newResolvedCallsite = true;
			}
		}

		// merged into a complete scc graph and merge intra-callsites
		Iterator<Function> sccIter = scc.iterator();
		Function selected = sccIter.next();
		Graph sccgraph = allBUGraphs.get(selected);
		while (sccgraph == null) {
			DebugUtil.print(selected.toString() + " has no BUGraph");
			if (!sccIter.hasNext())
				return;
			selected = sccIter.next();
			sccgraph = allBUGraphs.get(selected);
		}
		DebugUtil.print("Intra-SCC, select " + selected.toString());
		for (Function f : scc)
			sccgraph.funcArgMap.put(f, null);
		Map<DSNode, DSNode> isomorphism = new IdentityHashMap<DSNode, DSNode>();
		ArrayList<CallSiteNode> allCallSite = new ArrayList<CallSiteNode>();
		for (CallSiteNode cs : sccgraph.getCallNodes().values()) {
			if (!cs.getResolved() && cs.getFunc() != null && cs.getFunc().getParent() != null) {
				allCallSite.add(cs);
				DebugUtil.print("Intra-SCC, added " + cs.toString());
			}
		}

		HashSet<Address> visitedCS = new HashSet<Address>();
		while (allCallSite.size() > 0) {
			CallSiteNode cs = allCallSite.remove(0);
			if (visitedCS.contains(cs.getLoc())) {
				cs.setResolved(true);
				continue;
			}
			visitedCS.add(cs.getLoc());
			// start to merge at cs
			if (cs.getFunc().getParent() != null) {
				HashSet<Address> ptrs = new HashSet<Address>();
				for (Address funcAddr : cs.getFunc().getPossiblePointers()) {
					if (!funcAddr.isMemoryAddress())
						funcAddr = currentProgram.getAddressFactory().getAddress(
								currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
								funcAddr.getOffset());
					Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
					if (fp != null && scc.contains(fp) && allBUGraphs.get(fp) != null) {
						ptrs.add(funcAddr);
					}
				}
				for (Address funcAddr : ptrs) {
					Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
					if (fp != null && scc.contains(fp) && allBUGraphs.get(fp) != null) {
						// clone callee to the scc graph
						Graph callee = allBUGraphs.get(fp);
						sccgraph.cloneGraphIntoThis(callee, fp, cs, isomorphism);
						cs.setResolved(true);

						// add the callee's unresolved callsite into queue
						for (CallSiteNode cs2 : sccgraph.getCallNodes().values()) {
							if (!cs2.getResolved() && cs2.getFunc() != null && cs2.getFunc().getParent() != null) {
								allCallSite.add(cs2);
							}
						}

						// update the entry of callee in scc
						if (sccgraph.getF() != fp)
							if (sccgraph.funcArgMap.get(fp) == null) {
								sccgraph.funcArgMap.put(fp, cs);
							} else {
								// we are context-insensitive within the scc, all the callsites to f will be
								// merged
								CallSiteNode exist = sccgraph.funcArgMap.get(fp);
								exist.setResolved(true);
								sccgraph.mergeCallSite(exist, cs);
								cs = exist;
								if (allCallSite.contains(cs)) {
									int index = allCallSite.indexOf(cs);
									allCallSite.set(index, exist);
								}
							}
//						sccgraph.getCallNodes().remove(loc);
//						cs.addResolved(funcAddr);
						cs.setResolved(true);
						if (sccgraph.resolvedNewCallSite) {
							newResolvedCallsite = true;
						}
						allBUGraphs.put(fp, sccgraph);
					}
				}
			}

		}

		// new resolvable call sites
		if (newResolvedCallsite) {
			Function f = null;
			Iterator<Function> iter = scc.iterator();
			while (iter.hasNext()) {
				f = iter.next();
				val.put(f, -1);
				DebugUtil.print("unvisit " + f.toString());
				low.put(f, -1);
				if (allBUGraphs.get(f) == null)
					continue;
				allBUGraphs.get(f).resolvedNewCallSite = false;
			}
			if (f != null)
				tarjanVisitNode(f, inStack, low, val, stk);
		}
	}

	public void topDownAnalysis() {
		for (int i = sccs.size() - 1; i >= 0; i--) {
			HashSet<Function> scc = sccs.get(i);
			for (Function f : scc) {
				// resolve all function calls in the SCC
				Graph g = allBUGraphs.get(f);
				if (g == null)
					continue;
				HashSet<CallSiteNode> clonedcs = new HashSet<CallSiteNode>();
				clonedcs.addAll(g.getCallNodes().values());
				for (CallSiteNode cs : clonedcs) {
					if (cs.getResolved() && cs.getFunc() != null && cs.getFunc().getParent() != null
							&& cs.getCallPath().size() == 1) {
//						try {
//							BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
//									new FileOutputStream(IndirectCallTargetResolving.outPath, true)));
//							out.write(cs.toDetailedString());
//							out.newLine();
//							out.close();
//						} catch (Exception e) {
//							// TODO Auto-generated catch block
//							e.printStackTrace();
//						}

						for (Address funcAddr : cs.getFunc().getPossiblePointers()) {
							if (!funcAddr.isMemoryAddress())
								funcAddr = currentProgram.getAddressFactory().getAddress(
										currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
										funcAddr.getOffset());
							Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
							if (fp != null && !scc.contains(fp)) {
								resolveCaller(g, fp, cs);
							}
						}
					}
				}
			}
		}

	}

	public Set<Reference> getReferencesFromBody(Function caller, TaskMonitor monitor) {
		Set<Reference> set = new HashSet<>();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		AddressSetView addresses = caller.getBody();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			if (monitor.isCancelled()) {
				return set;
			}
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	public Set<Function> getCalledFunctions(Function caller, TaskMonitor monitor) {
		monitor = TaskMonitor.dummyIfNull(monitor);
		Set<Function> set = new HashSet<>();
		Set<Reference> references = getReferencesFromBody(caller, monitor);

		for (Reference reference : references) {
			if (monitor.isCancelled()) {
				return set;
			}
			if (reference.getReferenceType().isData())
				continue;
			Address toAddress = reference.getToAddress();
			Function calledFunction = currentProgram.getFunctionManager().getFunctionAt(toAddress);
			if (calledFunction != null) {
				set.add(calledFunction);
			}

		}
		return set;
	}


	public void bottomUpAnalysis(ArrayList<Function> functionList) {
		HashMap<Function, Integer> val = new HashMap<Function, Integer>();
		HashMap<Function, Integer> low = new HashMap<Function, Integer>();
		HashMap<Function, Boolean> inStack = new HashMap<Function, Boolean>();
		ArrayList<Function> stack = new ArrayList<Function>();
		for (Function func : functionList) {
			if (singleEntry && func.getCallingFunctions(monitor).size() == 0 && !GlobalState.targetFuncSuperSet.contains(func)) {
				DebugUtil.print("skip bottom-up for function " + func.getName());
				continue;
			}
			val.put(func, -1);
			low.put(func, -1);
			inStack.put(func, false);
			allBUGraphs.put(func, allLocalGraphs.get(func));
		}

		for (Function func : functionList) {
			if (val.containsKey(func) && val.get(func) == -1) {
				tarjanVisitNode(func, inStack, low, val, stack);
			}
		}

	}

	public void tarjanVisitNode(Function f, HashMap<Function, Boolean> inStack, HashMap<Function, Integer> low,
			HashMap<Function, Integer> val, ArrayList<Function> stk) {
		val.put(f, nextId);
		DebugUtil.print("tarjanVisitNode " + f.toString());
		low.put(f, nextId);
		nextId += 1;
		inStack.put(f, true);
		stk.add(f);

		Graph g = allBUGraphs.get(f);
		Set<Function> callees = new HashSet<Function>();

		if (g != null) {
			DebugUtil.print("# of getCallNodes: " + String.valueOf(g.getCallNodes().values().size()));
			for (CallSiteNode cs : g.getCallNodes().values()) {
				DebugUtil.print(cs.toString());
				if (cs.getFunc() != null && cs.getFunc().getParent() != null) {
					HashSet<Address> allAddr = new HashSet<Address>();
					allAddr.addAll(cs.getFunc().getPossiblePointers());
					DebugUtil.print(allAddr.toString());
					for (Address funcAddr : allAddr) {
						if (!funcAddr.isMemoryAddress())
							funcAddr = currentProgram.getAddressFactory().getAddress(
									currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
									funcAddr.getOffset());
						Function fp = this.currentProgram.getFunctionManager().getFunctionAt(funcAddr);
						if (fp != null) {
							callees.add(fp);
						}
					}
				}
			}
		} else
			callees.addAll(f.getCalledFunctions(monitor));

		for (Function callee : callees) {
			DebugUtil.print("callee: " + callee.getName());
			if (!val.containsKey(callee))
				continue;
			if (val.get(callee) == -1) {
				tarjanVisitNode(callee, inStack, low, val, stk);
				low.put(f, low.get(f) < low.get(callee) ? low.get(f) : low.get(callee));
			} else if (inStack.get(callee)) {
				low.put(f, low.get(f) < val.get(callee) ? low.get(f) : val.get(callee));
			}
		}

		if (low.get(f).intValue() == val.get(f).intValue()) {
			HashSet<Function> scc = new HashSet<Function>();
			while (true) {
				Function sccfunc = stk.remove(stk.size() - 1);
				scc.add(sccfunc);
				inStack.put(sccfunc, false);
				if (sccfunc == f)
					break;

			}
			processSCC(scc, stk, val, low, inStack);
		}
	}

	public void run() throws Exception {
		globalRegion = new GlobalRegion(currentProgram, allLocalGraphs, allMemAccessInstrMap);
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(currentProgram.getDataTypeManager().getRootCategory(), null, SourceType.USER_DEFINED, true, false);
		cmd.applyTo(currentProgram);
		
		GlobalState.decomplib = setUpDecompiler(this.currentProgram);
		GlobalState.currentProgram = this.currentProgram;
		if (!GlobalState.decomplib.openProgram(this.currentProgram)) {
			DebugUtil.printf("Decompiler error: %s\n", GlobalState.decomplib.getLastMessage());
			return;
		}
		FunctionModelManager.initAll();

		BufferedWriter out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(GlobalState.outPath)));
		out.close();
		out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(GlobalState.targetPath)));
		out.write(String.valueOf(currentProgram.getImageBase().getOffset()));
		out.newLine();
		out.close();
		out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(GlobalState.decompiledPath + "/IRs.txt")));
		out.close();

		long start = System.currentTimeMillis();
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		ArrayList<Function> funcList = new ArrayList<Function>();
		
//		defineGlobalType();

		// normal routine
		out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(GlobalState.memAccessPath)));
		for (Function func : functionManager) {
			out.write(Long.toHexString(func.getEntryPoint().getOffset()));
			out.newLine();	
			funcList.add(func);
		}
		out.close();

		for (Function func : funcList) {
			System.out.printf("Found target function %s @ %s %s, %.2f\n",
					new Object[] { func.getName(), Long.toHexString(func.getEntryPoint().getOffset()),
							this.currentProgram.getName(), (double) (funcList.size()) });
			DebugUtil.print(func.getName());

//			if (!func.getName().contains("InitSparePicture"))
//				continue;
			// local analysis phase
			analyzeLocalFuncs(func);
					
		}
		bottomUpAnalysis(funcList);
		handleUnresolvedCS();

		System.out.printf("runtime: %ds\n", (System.currentTimeMillis() - start) / 1000);
		System.out.printf("memory %dM\n",
				(Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024));

		topDownAnalysis();
		printMemAccess();
//		callGraphToJSON();
		
		// run checker
//		NPDChecker checker = new NPDChecker(currentProgram, allBUGraphs);
	}

	private void defineGlobalType() {
		SymbolTable symtab = this.currentProgram.getSymbolTable();
		MemoryBlock mem = currentProgram.getMemory().getBlock(".data");
		MemoryBlock bssmem = currentProgram.getMemory().getBlock(".bss");
        SymbolIterator symiter = symtab.getAllSymbols(true);
        HashMap<Address, Integer> datasize = new HashMap<Address, Integer>();
        Address lastAddr = null;
        int skip = 0;
        while (symiter.hasNext() && !this.monitor.isCancelled()) {
                Symbol sym = symiter.next();
                Address addr = sym.getAddress();
                if (!mem.contains(addr) && !bssmem.contains(addr))
                	continue;
                Data data = this.currentProgram.getListing().getDataAt(addr);
                if (data == null)
                    continue;
                System.out.println(sym.getName()); 
                if (sym.getName().startsWith("DAT_"))
                	skip += 1;
                else {
                	if (skip > 0 && lastAddr != null) {
                		skip = 0;
                		datasize.put(lastAddr, (int) (addr.getOffset() - 4 - lastAddr.getOffset()));
                	}
                	lastAddr = addr;
                }
        }
        
        for (Address addr : datasize.keySet()) {
        	int size = datasize.get(addr);
        	DebugUtil.print("change size at " + addr.toString() + " to " + size); 
        	DataType dt = BuiltInDataTypeManager.getDataTypeManager().getDataType("/undefined4");
			CreateArrayCmd cmd = new CreateArrayCmd(addr, size/4, dt, currentProgram.getDefaultPointerSize());
			cmd.applyTo(currentProgram);
        }
        return;
	}

	private void printMemAccess() {
		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(GlobalState.memAccessPath, true)));
			
			int tp = 0;
			int tn = 0;
			int fp = 0;
			int fn = 0;
			for (Address instr : allMemAccessInstrMap.keySet()) {
				for (Cell c : allMemAccessInstrMap.get(instr)) {
					if (c != null && c.getParent() != null) {
						DSNode parent2 = c.getParent();
						int field2 = c.getFieldOffset();
						int offset = field2 - parent2.getMinOffset();
						String locStr = "Mem Access " + instr.toString() + " -> offset" + String.valueOf(offset)
								+ " -> " + parent2.getLocations().toString();
						if (parent2.isArray() && GlobalState.conductCollapse) {
							ArrayList<Integer> keyset = new ArrayList<Integer>();
							keyset.addAll(parent2.getMembers().keySet());
							if (keyset.size() <= 1)
								locStr += " -> " + parent2.getSize();
							else if (parent2.hasStride())
								locStr += " -> " + parent2.getSize() + " -> " + parent2.getPossibleStride();
							else {
								Collections.sort(keyset);
								int id = keyset.indexOf(field2);
								if (keyset.size() > id + 1)
									locStr += " -> " + String.valueOf(keyset.get(id + 1) - field2);
								else
									locStr += " -> " + String.valueOf(parent2.getSize() - field2);
							}
							
						}
						Function f = currentProgram.getFunctionManager().getFunctionContaining(instr);
						if (parent2.getLocations().size() == 0) {
							if (f.getName().contains("good")) {
								fp += 1;
								DebugUtil.print("FP: " + locStr);
							}
							else if (f.getName().contains("bad")) {
								tp += 1;
								DebugUtil.print("TP: " + locStr);
							} else
								DebugUtil.print(locStr);
						} else {
							if (f.getName().contains("good")) {
								tn += 1;
								DebugUtil.print("TN: " + locStr);
							} else if (f.getName().contains("bad")) {
								fn += 1;
								DebugUtil.print("FN: " + locStr);
							}
						}

						out.write(locStr);
						out.newLine();
						
					} else {
						String locStr = "Mem Access " + instr.toString() + " -> offset 0"
						+ " -> []";
						out.write(locStr);
						out.newLine();
					}
				}
			}
			DebugUtil.print("TP: " + String.valueOf(tp));
			DebugUtil.print("FP: " + String.valueOf(fp));
			DebugUtil.print("TN: " + String.valueOf(tn));
			DebugUtil.print("FN: " + String.valueOf(fn));
			
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void handleUnresolvedCS() {

	}

	public String toString(PcodeOp p, Language l) {
		String s;
		if (p.getOutput() != null)
			s = toString(p.getOutput(), l);
		else
			s = " ";
		s += " " + p.getMnemonic() + " ";
		for (int i = 0; i < p.getNumInputs(); i++) {
			if (p.getInput(i) == null) {
				s += "null";
			} else {
				s += toString(p.getInput(i), l);
			}

			if (i < p.getNumInputs() - 1)
				s += " , ";
		}
//		s += " " + p.getSeqnum().toString();
		return s;
	}

	public String toString(Varnode v, Language language) {
		String varName = "";
		if (v.isAddress() || v.isRegister()) {
			Register reg = language.getRegister(v.getAddress(), v.getSize());
			if (reg != null) {
				varName = reg.getName();
				varName += '_' + String.valueOf(v.hashCode());
				return varName;
			}
		}
		if (v.isUnique()) {
			varName = "u_" + Long.toHexString(v.getOffset()) + ":" + v.getSize();
		} else if (v.isConstant()) {
			varName = "0x" + Long.toHexString(v.getOffset());
		} else {
			varName = "A_" + v.getAddress() + ":" + v.getSize();
		}
		varName += '_' + String.valueOf(v.hashCode());
		return varName;
	}

}


// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SEL (Mark Thurston). Part of ghidra-qingke-xw.
//
// Decompile every function of the current program and record, per function, whether the decompiler
// succeeded, whether its C uses a floating-point type, and how many distinct in_* / unaff_* variables it
// shows (registers read before anything in the function wrote them; a load decoded into the wrong
// register file leaves its real destination looking unset). Headless only.
//
// Argument: <out.tsv>, appended to (one run may import many objects).
// Output lines: program  function  ok|FAIL  float|-  nUnset  unsetNames  error  nHaltUnimplemented
//@category QingKeXW

import java.io.*;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		int ok = 0, fail = 0, fl = 0;
		try (PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(args[0], true), StandardCharsets.UTF_8)))) {
			out.println("# language\t" + currentProgram.getName() + "\t" + currentProgram.getLanguageID());
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (f.isExternal() || f.isThunk()) {
					continue;
				}
				DecompileResults r = di.decompileFunction(f, 60, monitor);
				boolean good = r != null && r.decompileCompleted() && r.getDecompiledFunction() != null;
				String c = good ? r.getDecompiledFunction().getC() : "";
				boolean usesFloat = c.matches("(?s).*\\b(float|double|float10|float8|float4)\\b.*");
				String err = (r == null || r.getErrorMessage() == null) ? ""
						: r.getErrorMessage().replace('\n', ' ').replace('\t', ' ');
				java.util.TreeSet<String> unset = new java.util.TreeSet<>();
				java.util.regex.Matcher m =
					java.util.regex.Pattern.compile("\\b(?:in|unaff)_[A-Za-z0-9_]+").matcher(c);
				while (m.find()) {
					unset.add(m.group());
				}
				// an instruction with no p-code ("unimpl") makes the decompiler emit halt_unimplemented()
				int halts = 0;
				java.util.regex.Matcher h = java.util.regex.Pattern.compile("\\bhalt_unimplemented\\b").matcher(c);
				while (h.find()) {
					halts++;
				}
				out.println(currentProgram.getName() + "\t" + f.getName() + "\t" + (good ? "ok" : "FAIL") +
					"\t" + (usesFloat ? "float" : "-") + "\t" + unset.size() + "\t" + String.join(",", unset) +
					"\t" + err + "\t" + halts);
				if (good) {
					ok++;
				}
				else {
					fail++;
				}
				if (usesFloat) {
					fl++;
				}
			}
		}
		di.dispose();
		println("DecompileCheck: " + currentProgram.getName() + " " + ok + " ok, " + fail + " failed, " + fl +
			" with float types");
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SEL (Mark Thurston). Part of ghidra-qingke-xw.
//
// Linear-sweep dump of every instruction Ghidra's language decodes, for the
// ghidra-qingke-xw proofs. Headless only.
//
// Arguments: <out.tsv> [<regions.tsv>]
//   regions.tsv: one region per line, "name<TAB>startHex<TAB>endHex", offsets
//   from the program's minimum address; each is swept on its own, from its
//   start, the way llvm-objdump sweeps a section. Without it, every
//   initialized block with execute permission is swept.
// Output, one line per decode attempt:
//   region  offsetHex  length  bytesHex  text  pcode
// text is "BAD" where Ghidra decodes nothing; the sweep then steps 2 bytes.
// pcode is written only for qk.* instructions (to check their semantics).
//@category QingKeXW

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;

public class DumpLinear extends GhidraScript {

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x", x & 0xff));
		}
		return sb.toString();
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: DumpLinear <out.tsv> [<regions.tsv>]");
		}
		Address base = currentProgram.getMinAddress();
		List<String[]> regions = new ArrayList<>();
		if (args.length >= 2) {
			for (String line : java.nio.file.Files.readAllLines(new File(args[1]).toPath(),
				StandardCharsets.UTF_8)) {
				if (line.isBlank()) {
					continue;
				}
				regions.add(line.split("\t"));
			}
		}
		else {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (b.isInitialized() && b.isExecute()) {
					long s = b.getStart().subtract(base);
					long e = b.getEnd().subtract(base) + 1;
					regions.add(new String[] { b.getName(), Long.toHexString(s), Long.toHexString(e) });
				}
			}
		}
		PseudoDisassembler pd = new PseudoDisassembler(currentProgram);
		long count = 0, bad = 0;
		try (PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(args[0]), StandardCharsets.UTF_8)))) {
			out.println("# language\t" + currentProgram.getLanguageID() + "\t" +
				currentProgram.getCompilerSpec().getCompilerSpecID());
			for (String[] r : regions) {
				String name = r[0];
				long start = Long.parseLong(r[1], 16);
				long end = Long.parseLong(r[2], 16);
				long off = start;
				out.println("# region\t" + name + "\t" + Long.toHexString(base.add(start).getOffset()));
				while (off < end) {
					monitor.checkCancelled();
					Address a = base.add(off);
					PseudoInstruction ins = null;
					try {
						ins = pd.disassemble(a);
					}
					catch (Exception ex) {
						ins = null;
					}
					if (ins != null && off + ins.getLength() <= end) {
						int len = ins.getLength();
						String text = ins.toString();
						String pc = "";
						if (ins.getMnemonicString().startsWith("qk.")) {
							StringBuilder sb = new StringBuilder();
							for (PcodeOp op : ins.getPcode()) {
								if (sb.length() > 0) {
									sb.append(" ; ");
								}
								sb.append(op.toString());
							}
							pc = sb.toString();
						}
						out.println(name + "\t" + Long.toHexString(off - start) + "\t" + len + "\t" +
							hex(ins.getBytes()) + "\t" + text + "\t" + pc);
						off += len;
						count++;
					}
					else {
						int n = (int) Math.min(2, end - off);
						byte[] b = new byte[n];
						currentProgram.getMemory().getBytes(a, b);
						out.println(name + "\t" + Long.toHexString(off - start) + "\t" + n + "\t" +
							hex(b) + "\tBAD\t");
						off += n;
						bad++;
					}
				}
			}
		}
		println("DumpLinear: " + count + " decoded, " + bad + " BAD, " + regions.size() + " regions -> " +
			args[0]);
	}
}

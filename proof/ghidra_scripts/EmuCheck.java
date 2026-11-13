// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SEL (Mark Thurston). Part of ghidra-qingke-xw.
//
// Run single instructions through Ghidra's p-code emulator, for the ghidra-qingke-xw "emu" proof.
// Headless only.
//
// Arguments: <cases.tsv> <out.tsv>
//   The program is a raw blob of instruction words loaded at 0. Each case line:
//     id  offsetHex  a0Hex  a1Hex  a2Hex
//   The script sets a0, a1, a2, sets pc to the offset, steps one instruction and writes:
//     id  a0Hex  a1Hex  a2Hex  pcHex  events
//   events lists every CALLOTHER (named operation) the instruction ran, ";"-separated, as
//     name(in1,in2,...)->outRegister
//   with each input's value in hex. A named operation with an output writes 5eed0000 + its sequence number
//   into it, so the caller can see where the output went. An error writes "ERROR <message>".
//@category QingKeXW

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public class EmuCheck extends GhidraScript {

	private final List<String> events = new ArrayList<>();
	private int seq = 0;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2) {
			throw new IllegalArgumentException("usage: EmuCheck <cases.tsv> <out.tsv>");
		}
		Address base = currentProgram.getMinAddress();
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		BreakCallBack cb = new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				MemoryState ms = emulate.getMemoryState();
				String name = emulate.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
				StringBuilder sb = new StringBuilder(name).append('(');
				for (int i = 1; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					long v = in.isConstant() ? in.getOffset() : ms.getValue(in);
					if (in.getSize() < 8) {
						v &= (1L << (8 * in.getSize())) - 1;
					}
					sb.append(i > 1 ? "," : "").append(Long.toHexString(v));
				}
				sb.append(')');
				Varnode out = op.getOutput();
				if (out != null) {
					Register r = currentProgram.getLanguage().getRegister(out.getAddress(), out.getSize());
					sb.append("->").append(r != null ? r.getName() : out.toString());
					ms.setValue(out, 0x5eed0000L + seq);
				}
				seq++;
				events.add(sb.toString());
				return true;
			}
		};
		emu.registerDefaultCallOtherCallback(cb);
		int n = 0, err = 0;
		try (PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(args[1]), StandardCharsets.UTF_8)))) {
			out.println("# language\t" + currentProgram.getLanguageID());
			for (String line : java.nio.file.Files.readAllLines(new File(args[0]).toPath(),
				StandardCharsets.UTF_8)) {
				if (line.isBlank() || line.startsWith("#")) {
					continue;
				}
				monitor.checkCancelled();
				String[] f = line.split("\t");
				events.clear();
				seq = 0;
				try {
					emu.writeRegister("a0", new BigInteger(f[2], 16));
					emu.writeRegister("a1", new BigInteger(f[3], 16));
					emu.writeRegister("a2", new BigInteger(f[4], 16));
					emu.writeRegister(emu.getPCRegister(), base.add(Long.parseLong(f[1], 16)).getOffset());
					if (!emu.step(monitor)) {
						throw new IllegalStateException("step failed: " + emu.getLastError());
					}
					out.println(f[0] + "\t" + emu.readRegister("a0").toString(16) + "\t" +
						emu.readRegister("a1").toString(16) + "\t" + emu.readRegister("a2").toString(16) + "\t" +
						emu.readRegister(emu.getPCRegister()).toString(16) + "\t" + String.join(";", events));
				}
				catch (Exception ex) {
					out.println(f[0] + "\tERROR " + String.valueOf(ex.getMessage()).replace('\t', ' ')
						.replace('\n', ' '));
					err++;
				}
				n++;
			}
		}
		emu.dispose();
		println("EmuCheck: " + n + " cases, " + err + " errors -> " + args[1]);
	}
}

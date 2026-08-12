using System.Runtime.InteropServices;
using Iced.Intel;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScannerLowLevel
{
    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn = false)
    {
        if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            return Arm64JumpTargets(codeStart, ignoreRetn);

        return JumpTargetsImpl(XrefScanner.DecoderForAddress(codeStart), ignoreRetn);
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(Decoder myDecoder, bool ignoreRetn)
    {
        var firstFlowControl = true;

        while (true)
        {
            myDecoder.Decode(out var instruction);
            if (myDecoder.LastError == DecoderError.NoMoreBytes) yield break;

            // 0xcc - padding after most functions
            if (instruction.Mnemonic == Mnemonic.Int3)
                yield break;

            if (instruction.FlowControl == FlowControl.Return && !ignoreRetn)
                yield break;

            if (instruction.FlowControl == FlowControl.UnconditionalBranch ||
                instruction.FlowControl == FlowControl.Call)
            {
                // We hope and pray that the compiler didn't use short jumps for any function calls
                if (!instruction.IsJmpShort)
                {
                    yield return (IntPtr)ExtractTargetAddress(in instruction);
                    if (firstFlowControl && instruction.FlowControl == FlowControl.UnconditionalBranch) yield break;
                }
            }

            if (instruction.FlowControl != FlowControl.Next)
            {
                firstFlowControl = false;
            }
        }
    }

    private static unsafe IntPtr[] Arm64JumpTargets(IntPtr codeStart, bool ignoreRetn)
    {
        const int maxInstructions = 512;
        var targets = new List<IntPtr>(16);
        var cursor = (byte*)codeStart;
        for (var i = 0; i < maxInstructions; i++)
        {
            var instruction = *(uint*)(cursor + i * 4);
            var pc = (ulong)(long)(cursor + i * 4);
            var op = instruction >> 26;

            if (op == 0b000101) // B imm26
            {
                var immediate = (int)(instruction << 6) >> 6;
                targets.Add((IntPtr)(pc + (ulong)((long)immediate << 2)));
                break;
            }

            if (op == 0b100101) // BL imm26
            {
                var immediate = (int)(instruction << 6) >> 6;
                targets.Add((IntPtr)(pc + (ulong)((long)immediate << 2)));
                continue;
            }

            if ((instruction & 0xFFFFFC1F) == 0xD65F0000) // RET
            {
                if (!ignoreRetn)
                    break;
            }
        }

        return targets.ToArray();
    }

    public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr pointer)
    {
        return CallAndIndirectTargetsImpl(XrefScanner.DecoderForAddress(pointer, 1024 * 1024));
    }

    private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(Decoder decoder)
    {
        while (true)
        {
            decoder.Decode(out var instruction);
            if (decoder.LastError == DecoderError.NoMoreBytes) yield break;

            if (instruction.FlowControl == FlowControl.Return)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Call || instruction.Mnemonic == Mnemonic.Jmp)
            {
                var targetAddress = XrefScanner.ExtractTargetAddress(instruction);
                if (targetAddress != 0)
                    yield return (IntPtr)targetAddress;
                continue;
            }

            if (instruction.Mnemonic == Mnemonic.Lea)
                if (instruction.MemoryBase == Register.RIP)
                {
                    var targetAddress = instruction.IPRelativeMemoryAddress;
                    if (targetAddress != 0)
                        yield return (IntPtr)targetAddress;
                }
        }
    }

    private static ulong ExtractTargetAddress(in Instruction instruction)
    {
        switch (instruction.Op0Kind)
        {
            case OpKind.NearBranch16:
                return instruction.NearBranch16;
            case OpKind.NearBranch32:
                return instruction.NearBranch32;
            case OpKind.NearBranch64:
                return instruction.NearBranch64;
            case OpKind.FarBranch16:
                return instruction.FarBranch16;
            case OpKind.FarBranch32:
                return instruction.FarBranch32;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }
}

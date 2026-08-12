using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using TerraFX.Interop.Windows;

namespace Il2CppInterop.Runtime;

internal static class WindowsMemoryUtils
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    [SupportedOSPlatform("windows6.1")]
    internal static unsafe nint FindSignatureInModule(ProcessModule module,
        MemoryUtils.SignatureDefinition sigDef)
    {
        const uint pageReadable = PAGE.PAGE_READONLY | PAGE.PAGE_READWRITE | PAGE.PAGE_WRITECOPY |
                                  PAGE.PAGE_EXECUTE_READ | PAGE.PAGE_EXECUTE_READWRITE |
                                  PAGE.PAGE_EXECUTE_WRITECOPY;
        var moduleEndAddress = (long)module.BaseAddress + module.ModuleMemorySize;
        var currentAddress = (long)module.BaseAddress;
        while (currentAddress < moduleEndAddress)
        {
            MEMORY_BASIC_INFORMATION memoryInfo = default;
            var result = Windows.VirtualQuery((void*)currentAddress, &memoryInfo,
                (nuint)sizeof(MEMORY_BASIC_INFORMATION));
            if (result == 0)
                break;

            if (memoryInfo.State == MEM.MEM_COMMIT && (memoryInfo.Protect & PAGE.PAGE_GUARD) == 0 &&
                (memoryInfo.Protect & pageReadable) != 0)
            {
                var ptr = MemoryUtils.FindSignatureInBlock((nint)memoryInfo.BaseAddress,
                    (long)memoryInfo.RegionSize, sigDef.pattern, sigDef.mask, sigDef.offset);
                if (ptr != 0)
                    return ptr;
            }

            currentAddress = (long)memoryInfo.BaseAddress + (long)memoryInfo.RegionSize;
        }

        return 0;
    }
}

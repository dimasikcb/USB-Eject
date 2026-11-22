#requires -Version 5.1
<#
.SYNOPSIS
  USB-Eject — принудительное извлечение USB-накопителей из консоли.
.DESCRIPTION
  1. Закрывает окна Проводника, открытые на выбранном диске.
  2. Находит процессы, удерживающие файлы/том диска (скан хэндлов), показывает
     ЧТО мешает: службы, программы, Проводник или системные процессы —
     и даёт выбрать, что остановить (можно только службы).
  3. Блокирует и размонтирует том, затем выключает USB-устройство
     (CM_Request_Device_Eject, при отказе — IOCTL_STORAGE_EJECT_MEDIA).
  4. Остановленные службы запускает обратно после успешного извлечения.
.EXAMPLE
  USB-Eject.bat                 # интерактивно: список дисков -> ввод буквы
  USB-Eject.bat E               # сразу извлечь диск E:
  powershell -File USB-Eject.ps1 -List       # список USB-дисков
  powershell -File USB-Eject.ps1 -Scan C      # показать, кто держит диск C: (только чтение)
#>
param(
    [Parameter(Position = 0)]
    [string]$Drive = '',
    [switch]$List,
    [switch]$Scan,
    [switch]$Kill,
    [switch]$Yes,
    [switch]$NoPause,
    [switch]$NoElevate
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# --- Самоповышение: без прав администратора скрипт перезапускает сам себя от админа ---
if (-not $script:IsAdmin -and -not $NoElevate) {
    $argStr = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    if ($Drive) { $argStr += (' "{0}"' -f $Drive) }
    foreach ($sw in @('List', 'Scan', 'Kill', 'Yes', 'NoPause')) {
        if ((Get-Variable -Name $sw -ErrorAction SilentlyContinue).Value) { $argStr += " -$sw" }
    }
    Write-Host "Запрашиваю права администратора (UAC)..." -ForegroundColor Cyan
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argStr -Verb RunAs -Wait | Out-Null
    } catch {
        Write-Host "Отменено: для остановки служб и извлечения нужны права администратора." -ForegroundColor Yellow
        if (-not $NoPause) { try { [void](Read-Host "Нажмите Enter для выхода") } catch {} }
    }
    exit 0
}

# Процессы, которые нельзя завершать никогда
$script:NeverKill = @('winlogon', 'csrss', 'smss', 'services', 'lsass', 'wininit', 'MemCompression', 'Registry', 'System', 'Idle')
# Службы, остановленные по ходу работы (запускаем обратно после извлечения)
$script:StoppedSvc = @()

if (-not ('UsbEject.Native' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace UsbEject
{
    public class OpenHandle
    {
        public int Pid;
        public string Path;
    }

    public static class Native
    {
        [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int need);
        [DllImport("ntdll.dll")] private static extern int NtQueryObject(IntPtr h, int cls, IntPtr buf, int len, out int need);
        [DllImport("ntdll.dll")] private static extern int NtQueryVolumeInformationFile(IntPtr h, IntPtr iosb, IntPtr fsInfo, uint len, uint fsInfoClass);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, uint access, bool inherit, uint opts);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern uint GetFinalPathNameByHandleW(IntPtr h, [Out] StringBuilder path, uint len, uint flags);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern uint QueryDosDeviceW(string name, StringBuilder target, int max);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inSize, IntPtr outBuf, uint outSize, out uint ret, IntPtr ov);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FlushFileBuffers(IntPtr h);
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr h, StringBuilder cls, int max);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr h, StringBuilder txt, int max);
        [DllImport("user32.dll")] private static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern int CM_Request_Device_Eject_ExW(string deviceId, out int vetoType, StringBuilder vetoName, uint vetoNameLength, uint flags, IntPtr machineHandle);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern int CM_Locate_DevNodeW(out int devInst, string deviceId, uint flags);
        [DllImport("cfgmgr32.dll")] private static extern int CM_Get_Parent(out int parent, int devInst, uint flags);
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern int CM_Get_Device_IDW(int devInst, StringBuilder id, int len, uint flags);

        private const int SystemExtendedHandleInformation = 64;
        private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
        private const uint ProcessDupHandle = 0x0040;
        private const uint DuplicateSameAccess = 0x0002;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint ShareReadWriteDelete = 0x7;
        private const uint OpenExisting = 3;
        private const uint FsctlLockVolume = 0x00090018;
        private const uint FsctlDismountVolume = 0x0009001C;
        private const uint IoctlStorageEjectMedia = 0x002D4808;
        private const uint WmClose = 0x0010;
        private const uint CmRequestDeviceEjectNoUi = 0x1;
        private const uint FileFsDeviceInformation = 4;
        private const uint DeviceTypeDisk = 0x7;
        private const uint DeviceTypeDiskFileSystem = 0x8;

        [StructLayout(LayoutKind.Sequential)]
        private struct HandleEntryEx
        {
            public ulong Object;
            public ulong ProcessId;
            public IntPtr Handle;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            public IntPtr StatusPointer;
            public IntPtr Information;
        }

        private static string ReadUnicodeString(IntPtr infoBuffer)
        {
            short len = Marshal.ReadInt16(infoBuffer, 0);
            IntPtr str = Marshal.ReadIntPtr(infoBuffer, IntPtr.Size);
            if (len <= 0 || str == IntPtr.Zero) return null;
            return Marshal.PtrToStringUni(str, len / 2);
        }

        private static string PathWithTimeout(IntPtr dup, int timeoutMs, out bool timedOut)
        {
            timedOut = false;
            var sb = new StringBuilder(4096);
            int got = 0;
            var t = new Thread(delegate() { try { got = (int)GetFinalPathNameByHandleW(dup, sb, 4096, 0); } catch { } });
            t.IsBackground = true;
            t.Start();
            if (!t.Join(timeoutMs)) { timedOut = true; return null; }
            return got > 0 ? sb.ToString() : null;
        }

        private static string NtNameWithTimeout(IntPtr dup, int timeoutMs, out bool timedOut)
        {
            timedOut = false;
            IntPtr buf = Marshal.AllocHGlobal(4096);
            try
            {
                string name = null;
                var t = new Thread(delegate() { try { int need; if (NtQueryObject(dup, 1 /*ObjectNameInformation*/, buf, 4096, out need) == 0) name = ReadUnicodeString(buf); } catch { } });
                t.IsBackground = true;
                t.Start();
                if (!t.Join(timeoutMs)) { timedOut = true; return null; }
                return name;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // Находит открытые дескрипторы (файлы/том), относящиеся к заданному диску.
        public static List<OpenHandle> FindOpenHandles(char letter, int currentPid, string[] extraPrefixes, out int leaked)
        {
            leaked = 0;
            var result = new List<OpenHandle>();
            string dosPrefix = letter.ToString().ToLowerInvariant() + ":";
            string volDos = ("\\\\.\\" + letter + ":").ToLowerInvariant();
            var qd = new StringBuilder(1024);
            var prefixes = new List<string>();
            prefixes.Add(dosPrefix);
            prefixes.Add(volDos);
            if (QueryDosDeviceW(letter + ":", qd, 1024) > 0 && qd.Length > 0)
                prefixes.Add(qd.ToString().ToLowerInvariant());
            if (extraPrefixes != null)
                foreach (string p in extraPrefixes)
                    if (!string.IsNullOrEmpty(p)) prefixes.Add(p.ToLowerInvariant());

            int len = 0x400000;
            IntPtr buf = IntPtr.Zero;
            int status = StatusInfoLengthMismatch, need;
            while (true)
            {
                buf = Marshal.AllocHGlobal(len);
                status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, len, out need);
                if (status == StatusInfoLengthMismatch)
                {
                    Marshal.FreeHGlobal(buf);
                    buf = IntPtr.Zero;
                    len = need > len ? need : len * 2;
                    if (len > 0x10000000) break;
                    continue;
                }
                break;
            }
            if (status != 0 || buf == IntPtr.Zero) return result;

            try
            {
                long count = Marshal.ReadIntPtr(buf).ToInt64();
                int entrySize = Marshal.SizeOf(typeof(HandleEntryEx));
                long baseAddr = buf.ToInt64() + IntPtr.Size * 2;
                var procCache = new Dictionary<int, IntPtr>();
                int stuck = 0;
                var sw = System.Diagnostics.Stopwatch.StartNew();
                for (long i = 0; i < count; i++)
                {
                    if ((i & 0x3FF) == 0)
                    {
                        int pct = (int)(i * 100L / (count > 0 ? count : 1L));
                        double remain = pct >= 5 ? Math.Round(sw.Elapsed.TotalSeconds * (100.0 - pct) / pct) : -1;
                        if (remain >= 0)
                            Console.Write("\r  Прогресс: {0}%  (осталось ~{1} с)   ", pct, remain);
                        else
                            Console.Write("\r  Прогресс: {0}%   ", pct);
                    }
                    if (stuck > 200) break;
                    var entry = (HandleEntryEx)Marshal.PtrToStructure(new IntPtr(baseAddr + i * entrySize), typeof(HandleEntryEx));
                    int pid = (int)(entry.ProcessId & 0xFFFFFFFFL);
                    if (pid <= 4 || pid == currentPid) continue;
                    if ((entry.GrantedAccess & 0x0012019F) == 0) continue;

                    IntPtr proc;
                    if (!procCache.TryGetValue(pid, out proc))
                    {
                        proc = OpenProcess(ProcessDupHandle, false, pid);
                        procCache[pid] = proc;
                    }
                    if (proc == IntPtr.Zero) continue;

                    IntPtr dup;
                    if (!DuplicateHandle(proc, entry.Handle, GetCurrentProcess(), out dup, 0, false, DuplicateSameAccess)) continue;

                    string typeName = null;
                    IntPtr tbuf = Marshal.AllocHGlobal(4096);
                    try
                    {
                        int tneed;
                        if (NtQueryObject(dup, 2 /*ObjectTypeInformation*/, tbuf, 4096, out tneed) == 0) typeName = ReadUnicodeString(tbuf);
                    }
                    finally { Marshal.FreeHGlobal(tbuf); }
                    if (typeName != "File") { CloseHandle(dup); continue; }

                    // Быстрый фильтр: интересуют только файлы/тома на ДИСКАХ.
                    // Трубы, маилслоты и прочее отсекаем мгновенно по типу устройства — без таймаутов.
                    // Если запрос типа не удался — не отсеиваем, идём безопасным путём с таймаутом.
                    IntPtr iosb = Marshal.AllocHGlobal(32);
                    IntPtr fsBuf = Marshal.AllocHGlobal(16);
                    bool typeKnown = false;
                    uint devType = 0;
                    try
                    {
                        if (NtQueryVolumeInformationFile(dup, iosb, fsBuf, 16, FileFsDeviceInformation) == 0)
                        {
                            devType = (uint)Marshal.ReadInt32(fsBuf, 0);
                            typeKnown = true;
                        }
                    }
                    finally { Marshal.FreeHGlobal(iosb); Marshal.FreeHGlobal(fsBuf); }
                    if (typeKnown && devType != DeviceTypeDisk && devType != DeviceTypeDiskFileSystem) { CloseHandle(dup); continue; }

                    string path;
                    if (typeKnown)
                    {
                        var sb = new StringBuilder(4096);
                        uint got = GetFinalPathNameByHandleW(dup, sb, 4096, 0);
                        path = got > 0 ? sb.ToString() : null;
                    }
                    else
                    {
                        bool timedOut;
                        path = PathWithTimeout(dup, 200, out timedOut);
                        if (timedOut) { leaked++; stuck++; continue; }
                    }
                    if (string.IsNullOrEmpty(path))
                    {
                        bool timedOut2;
                        path = NtNameWithTimeout(dup, 200, out timedOut2);
                        if (timedOut2) { leaked++; stuck++; continue; }
                        if (string.IsNullOrEmpty(path)) { CloseHandle(dup); continue; }
                    }

                    string low = path.ToLowerInvariant();
                    if (low.StartsWith(@"\\?\")) low = low.Substring(4);

                    bool match = false;
                    foreach (string p in prefixes)
                    {
                        if (low == p || low.StartsWith(p + "\\")) { match = true; break; }
                    }
                    if (!match) { CloseHandle(dup); continue; }

                    result.Add(new OpenHandle { Pid = pid, Path = path });
                }
                Console.Write("\r" + new string(' ', 70) + "\r");
            }
            finally { Marshal.FreeHGlobal(buf); }
            return result;
        }

        // Человеческое объяснение отказа Windows в извлечении (PNP_VETO_TYPE)
        private static string VetoText(int t)
        {
            switch (t)
            {
                case 1: return "устройство блокирует legacy-драйвер";
                case 2: return "устройство ещё закрывается, подожди немного";
                case 3: return "приложение Windows использует устройство";
                case 4: return "запущена служба устройства";
                case 5: return "какой-то процесс держит открытым дескриптор устройства";
                case 6: return "ресурс устройства занят";
                case 7: return "устройство отключено по умолчанию системой";
                case 8: return "устройство используется legacy-службой";
                case 9: return "недостаточно прав для извлечения";
                default: return "причина не сообщена";
            }
        }

        // Извлечение через диспетчер устройств (то же, что "безопасное извлечение").
        // Флаг NO_UI: Windows НЕ показывает своё окно "устройство ещё используется",
        // причину отказа мы сообщаем сами в консоли.
        private static string TryCmEject(string instanceId)
        {
            if (string.IsNullOrEmpty(instanceId)) return "нет идентификатора устройства (InstanceId)";
            int vetoType;
            var veto = new StringBuilder(512);
            int cr = CM_Request_Device_Eject_ExW(instanceId, out vetoType, veto, (uint)veto.Capacity, CmRequestDeviceEjectNoUi, IntPtr.Zero);
            if (cr == 0) return null;
            int devInst, parent;
            var id = new StringBuilder(1024);
            if (CM_Locate_DevNodeW(out devInst, instanceId, 0) == 0 &&
                CM_Get_Parent(out parent, devInst, 0) == 0 &&
                CM_Get_Device_IDW(parent, id, id.Capacity, 0) == 0)
            {
                int vetoType2;
                var veto2 = new StringBuilder(512);
                if (CM_Request_Device_Eject_ExW(id.ToString(), out vetoType2, veto2, (uint)veto2.Capacity, CmRequestDeviceEjectNoUi, IntPtr.Zero) == 0) return null;
            }
            return "Windows отказала в извлечении на уровне PnP (причина: " + VetoText(vetoType) + (veto.Length > 0 ? " [" + veto.ToString() + "]" : "") + ")";
        }

        // Резерв: команда EJECT самому физическому диску.
        private static string TryIoctlEject(string physicalDrive)
        {
            if (string.IsNullOrEmpty(physicalDrive)) return "нет пути физического диска";
            IntPtr d = CreateFileW(physicalDrive, GenericRead | GenericWrite, 0x3, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (d == IntPtr.Zero || d == new IntPtr(-1)) return "не удалось открыть " + physicalDrive + " (ошибка " + Marshal.GetLastWin32Error() + ")";
            try
            {
                uint ret;
                if (DeviceIoControl(d, IoctlStorageEjectMedia, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero)) return null;
                return "ошибка " + Marshal.GetLastWin32Error();
            }
            finally { CloseHandle(d); }
        }

        // Полный цикл: сброс кэша -> блокировка/размонтирование тома -> выключение устройства.
        // vetoInfo — примечание, если Windows препятствовала извлечению на уровне PnP.
        public static string EjectDevice(char letter, string instanceId, string physicalDrive, out string vetoInfo)
        {
            vetoInfo = "";
            string volName = "\\\\.\\" + letter + ":";
            IntPtr h = CreateFileW(volName, GenericRead | GenericWrite, ShareReadWriteDelete, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            bool haveVol = (h != IntPtr.Zero && h != new IntPtr(-1));
            if (!haveVol)
            {
                string m = TryCmEject(instanceId);
                if (m == null) return null;
                m = TryIoctlEject(physicalDrive);
                if (m == null) { vetoInfo = "том открыт не был, но диск выключен командой eject"; return null; }
                return "не удалось открыть том " + volName + " (ошибка " + Marshal.GetLastWin32Error() + "); " + m;
            }
            try
            {
                uint ret;
                try { FlushFileBuffers(h); } catch { }
                bool locked = DeviceIoControl(h, FsctlLockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                bool dismounted = false;
                if (!locked)
                {
                    dismounted = DeviceIoControl(h, FsctlDismountVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                    if (dismounted)
                        locked = DeviceIoControl(h, FsctlLockVolume, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                }
                string cmReason = TryCmEject(instanceId);
                if (cmReason == null) return null;
                string m = TryIoctlEject(physicalDrive);
                if (m == null) { vetoInfo = cmReason + "; но диск выключен командой eject — отсоединять можно"; return null; }
                if (dismounted)
                    return "том размонтирован, но устройство не выключено (" + m + ")";
                return "том занят: не удалось заблокировать/размонтировать (" + m + ")";
            }
            finally { CloseHandle(h); }
        }

        // Закрытие окон Проводника, открытых на корне диска (заголовок вида "Tom (E:)").
        public static int CloseExplorerWindows(char letter)
        {
            int closed = 0;
            string needle = "(" + letter.ToString().ToLowerInvariant() + ":)";
            EnumWindows(delegate(IntPtr h, IntPtr lp)
            {
                var cls = new StringBuilder(256);
                GetClassNameW(h, cls, 256);
                string c = cls.ToString();
                if (c != "CabinetWClass" && c != "ExploreWClass") return true;
                var txt = new StringBuilder(512);
                GetWindowTextW(h, txt, 512);
                if (txt.ToString().ToLowerInvariant().Contains(needle))
                {
                    if (PostMessageW(h, WmClose, IntPtr.Zero, IntPtr.Zero)) closed++;
                }
                return true;
            }, IntPtr.Zero);
            return closed;
        }
    }
}
'@
}

# ---------- Вспомогательные функции ----------

function Get-Targets {
    $out = @()
    $seen = @{}
    $diskDevs = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
    $storageDisks = @()
    try { $storageDisks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'USB' }) } catch {}
    foreach ($d in $storageDisks) {
        $dev = $diskDevs | Where-Object { $null -ne $_.Index -and [int]$_.Index -eq [int]$d.Number } | Select-Object -First 1
        $letters = @()
        try {
            $letters = @(Get-Partition -DiskNumber ([int]$d.Number) -ErrorAction Stop | Where-Object { $_.DriveLetter } | ForEach-Object { $_.DriveLetter })
        } catch {}
        foreach ($l in $letters) {
            $lc = [char]$l
            if ($seen.ContainsKey($lc)) { continue }
            $seen[$lc] = $true
            $v = Get-Volume -DriveLetter $lc -ErrorAction SilentlyContinue
            $out += [pscustomobject]@{
                Letter        = $lc
                Label         = $(if ($v -and $v.FileSystemLabel) { $v.FileSystemLabel } else { '(без метки)' })
                FS            = $(if ($v) { $v.FileSystem } else { '?' })
                SizeGB        = $(if ($v) { [math]::Round($v.Size / 1GB, 1) } else { 0 })
                Model         = $d.FriendlyName
                DiskNumber    = [int]$d.Number
                InstanceId    = $(if ($dev) { $dev.PNPDeviceID } else { $null })
                PhysicalDrive = "\\.\PhysicalDrive$($d.Number)"
            }
        }
    }
    try {
        foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue)) {
            $lc = [char]([string]$ld.DeviceID[0])
            if ($seen.ContainsKey($lc)) { continue }
            $seen[$lc] = $true
            $part = Get-Partition -DriveLetter $lc -ErrorAction SilentlyContinue
            $dev = $null; $dn = $null
            if ($part) {
                $dn = [int]$part.DiskNumber
                $dev = $diskDevs | Where-Object { $null -ne $_.Index -and [int]$_.Index -eq $dn } | Select-Object -First 1
            }
            $out += [pscustomobject]@{
                Letter        = $lc
                Label         = $(if ($ld.VolumeName) { $ld.VolumeName } else { '(без метки)' })
                FS            = $ld.FileSystem
                SizeGB        = $(if ($ld.Size) { [math]::Round($ld.Size / 1GB, 1) } else { 0 })
                Model         = 'Съёмный носитель'
                DiskNumber    = $dn
                InstanceId    = $(if ($dev) { $dev.PNPDeviceID } else { $null })
                PhysicalDrive = $(if ($null -ne $dn) { "\\.\PhysicalDrive$dn" } else { $null })
            }
        }
    } catch {}
    return @($out)
}

function Show-Targets {
    param($Targets)
    Write-Host ""
    Write-Host "USB / съёмные диски:" -ForegroundColor Cyan
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-Host "  (не найдено — подключите накопитель и перезапустите)" -ForegroundColor DarkGray
        return
    }
    foreach ($t in $Targets) {
        Write-Host ("  {0}: «{1}»  {2}  {3} GB, {4}  (диск #{5})" -f $t.Letter, $t.Label, $t.FS, $t.SizeGB, $t.Model, $t.DiskNumber)
    }
}

function Close-ExplorerWindows {
    param([char]$Letter)
    $closed = 0
    try {
        $shell = New-Object -ComObject Shell.Application
        $low = $Letter.ToString().ToLower()
        foreach ($w in @($shell.Windows())) {
            try {
                $path = $null
                if ($w.Document -and $w.Document.Folder) { $path = $w.Document.Folder.Self.Path }
                if (-not $path) {
                    $u = $null; try { $u = $w.LocationURL } catch {}
                    if ($u -and $u.ToLower().StartsWith("file:///$low")) { $path = "$($Letter):" }
                }
                if ($path) {
                    $pl = $path.ToLower()
                    if ($pl.StartsWith("$low") -or $pl.StartsWith("\\?\$low") -or $pl.StartsWith("\\.\$low")) {
                        $w.Quit(); $closed++
                    }
                }
            } catch {}
        }
    } catch {}
    $closed += [UsbEject.Native]::CloseExplorerWindows($Letter)
    return $closed
}

function Get-BlockingProcesses {
    param([char]$Letter, [string[]]$ExtraPrefixes = @())
    $leaked = 0
    $raw = [UsbEject.Native]::FindOpenHandles($Letter, $PID, $ExtraPrefixes, [ref]$leaked)

    # Карта PID -> службы (кто хостится в процессе)
    $svcMap = @{}
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 })) {
            $spid = [int]$s.ProcessId
            if (-not $svcMap.ContainsKey($spid)) { $svcMap[$spid] = @() }
            $svcMap[$spid] += [pscustomobject]@{ Name = [string]$s.Name; DisplayName = [string]$s.DisplayName }
        }
    } catch {}

    $out = @()
    foreach ($g in @($raw | Group-Object -Property Pid)) {
        $pidInt = [int]$g.Name
        $proc = Get-Process -Id $pidInt -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { '?' }
        $desc = ''
        try { if ($proc) { $desc = [string]$proc.Description } } catch {}
        $svcs = @()
        if ($svcMap.ContainsKey($pidInt)) { $svcs = @($svcMap[$pidInt]) }

        $category = 'app'
        if ($pidInt -le 4 -or $procName -in $script:NeverKill) { $category = 'system' }
        elseif ($procName -eq 'explorer') { $category = 'explorer' }
        elseif ($svcs.Count -gt 0) { $category = 'service' }

        $paths = @($g.Group | ForEach-Object { $_.Path } | ForEach-Object { if ($_.StartsWith('\\?\')) { $_.Substring(4) } else { $_ } } | Select-Object -Unique)
        $out += [pscustomobject]@{
            Pid      = $pidInt
            Name     = $procName
            Desc     = $desc
            Title    = $(if ($proc -and $proc.MainWindowTitle) { $proc.MainWindowTitle } else { '' })
            Files    = $paths.Count
            Paths    = (($paths | Select-Object -First 6) -join "`n        ")
            Services = $svcs
            Category = $category
        }
    }

    $rank = @{ service = 0; app = 1; explorer = 2; system = 3 }
    $sorted = @($out | Sort-Object { $rank[[string]$_.Category] }, Name, Pid)
    $num = 0
    $final = @($sorted | ForEach-Object { $num++; $_ | Add-Member -NotePropertyName Num -NotePropertyValue $num -Force -PassThru })
    [pscustomobject]@{ Processes = $final; Leaked = $leaked }
}

function Show-Blockers {
    param($Procs)
    if (-not $Procs -or $Procs.Count -eq 0) {
        Write-Host "Блокирующие процессы не найдены." -ForegroundColor Green
        return
    }
    Write-Host ("Держателей: {0}. Что мешает извлечению:" -f $Procs.Count) -ForegroundColor Yellow
    foreach ($it in $Procs) {
        $hint = switch ($it.Category) {
            'service'  { "это служба Windows — останавливать безопасно, после извлечения запустится сама" }
            'explorer' { "открытые окна диска и кэш миниатюр — закрывать безопасно" }
            'app'      { "программа открыла файлы с диска — если она что-то записывает, несохранённое пропадёт" }
            'system'   { "защищённый процесс Windows — завершать нельзя, но извлечение обычно срабатывает и так" }
        }
        switch ($it.Category) {
            'service' {
                $svcs = ($it.Services | ForEach-Object { "{0} [{1}]" -f $_.DisplayName, $_.Name }) -join ', '
                Write-Host ("  [{0}] СЛУЖБА    {1}  (PID {2}, файлов: {3})" -f $it.Num, $svcs, $it.Pid, $it.Files) -ForegroundColor Cyan
            }
            'explorer' {
                Write-Host ("  [{0}] ПРОВОДНИК Проводник Windows  (PID {1}, файлов: {2})" -f $it.Num, $it.Pid, $it.Files) -ForegroundColor Yellow
            }
            'app' {
                $dn = if ($it.Desc) { $it.Desc } else { $it.Name }
                $t = if ($it.Title) { " «$($it.Title)»" } else { '' }
                Write-Host ("  [{0}] ПРОГРАММА {1}{2}  ({3}, PID {4}, файлов: {5})" -f $it.Num, $dn, $t, $it.Name, $it.Pid, $it.Files) -ForegroundColor Yellow
            }
            'system' {
                Write-Host ("  [{0}] СИСТЕМА   {1}  (PID {2}, файлов: {3}) — завершать нельзя" -f $it.Num, $it.Name, $it.Pid, $it.Files) -ForegroundColor DarkYellow
            }
        }
        Write-Host "        > простыми словами: $hint" -ForegroundColor DarkCyan
        if ($it.Paths) { Write-Host "        файлы: $($it.Paths)" -ForegroundColor DarkGray }
    }
}

function Show-Verdict {
    param($Procs)
    $apps = @($Procs | Where-Object { $_.Category -eq 'app' })
    if (-not $Procs -or $Procs.Count -eq 0) {
        Write-Host "Вердикт: диск свободен — можно извлекать." -ForegroundColor Green
    } elseif ($apps.Count -gt 0) {
        Write-Host "Вердикт: осторожно — программы держат файлы с диска. Сохрани в них работу, если что-то записывалось." -ForegroundColor Yellow
    } else {
        Write-Host "Вердикт: извлекать безопасно — держат только окна Проводника, службы или система." -ForegroundColor Green
    }
}

function Invoke-StopBlockers {
    param($Items)
    foreach ($it in $Items) {
        if ($it.Category -eq 'system') { continue }
        if ($it.Category -eq 'service') {
            foreach ($s in @($it.Services)) {
                try {
                    Stop-Service -Name $s.Name -Force -ErrorAction Stop
                    Write-Host ("  [ok] служба остановлена: {0} [{1}]" -f $s.DisplayName, $s.Name) -ForegroundColor Green
                    if ($script:StoppedSvc -notcontains $s.Name) { $script:StoppedSvc += $s.Name }
                } catch {
                    Write-Host ("  [!!] служба {0}: {1}" -f $s.Name, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
            # Общий svchost не убиваем процессом — только служба; отдельный процесс службы добиваем при необходимости
            if ($it.Name -ne 'svchost') {
                Start-Sleep -Milliseconds 1500
                if (Get-Process -Id $it.Pid -ErrorAction SilentlyContinue) {
                    try { Stop-Process -Id $it.Pid -Force -ErrorAction Stop; Write-Host ("  [ok] процесс службы остановлен: {0} (PID {1})" -f $it.Name, $it.Pid) -ForegroundColor Green }
                    catch { Write-Host ("  [!!] процесс {0} (PID {1}): {2}" -f $it.Name, $it.Pid, $_.Exception.Message) -ForegroundColor Yellow }
                } else {
                    Write-Host ("  [ok] процесс службы завершился: {0} (PID {1})" -f $it.Name, $it.Pid) -ForegroundColor Green
                }
            }
        }
        elseif ($it.Category -eq 'explorer') {
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
            Write-Host "  [ok] Проводник перезапущен" -ForegroundColor Green
        }
        else {
            $p = Get-Process -Id $it.Pid -ErrorAction SilentlyContinue
            if ($p -and $p.MainWindowTitle) {
                try { [void]$p.CloseMainWindow(); Start-Sleep -Milliseconds 1200 } catch {}
            }
            if (Get-Process -Id $it.Pid -ErrorAction SilentlyContinue) {
                try { Stop-Process -Id $it.Pid -Force -ErrorAction Stop; Write-Host ("  [ok] завершено: {0} (PID {1})" -f $it.Name, $it.Pid) -ForegroundColor Green }
                catch { Write-Host ("  [!!] {0} (PID {1}): {2}" -f $it.Name, $it.Pid, $_.Exception.Message) -ForegroundColor Yellow }
            } else {
                Write-Host ("  [ok] завершилось само: {0} (PID {1})" -f $it.Name, $it.Pid) -ForegroundColor Green
            }
        }
    }
}

function Restart-StoppedServices {
    if (-not $script:StoppedSvc -or $script:StoppedSvc.Count -eq 0) { return }
    Write-Host ""
    Write-Host "Возвращаю остановленные службы..." -ForegroundColor Cyan
    foreach ($sn in $script:StoppedSvc) {
        try { Start-Service -Name $sn -ErrorAction Stop; Write-Host ("  [ok] служба запущена: {0}" -f $sn) -ForegroundColor Green }
        catch { Write-Host ("  [!!] служба {0}: {1}" -f $sn, $_.Exception.Message) -ForegroundColor Yellow }
    }
    $script:StoppedSvc = @()
}

function Remove-DeviceNodeSilent {
    param([string]$InstanceId)
    if (-not $InstanceId) { return $false }
    $null = & "$env:SystemRoot\System32\pnputil.exe" /remove-device "$InstanceId" 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Test-SpecialUse {
    param([char]$Letter)
    $notes = @()
    try {
        foreach ($pf in @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)) {
            if ($pf.Name -and $pf.Name.ToUpper().StartsWith([string]$Letter + ':')) {
                $notes += "на диске находится файл подкачки ($($pf.Name)) — пока он там, извлечение невозможно"
            }
        }
    } catch {}
    if (Test-Path ($Letter.ToString() + ':\ReadyBoost.sfcf')) {
        $notes += "диск используется ReadyBoost — отключите его в свойствах диска"
    }
    return $notes
}

# ---------- Основной сценарий ----------

try {
    Write-Host "=== USB-Eject — безопасное/принудительное извлечение USB-дисков ===" -ForegroundColor Cyan
    if (-not $script:IsAdmin) {
        Write-Host "! Запущено с -NoElevate: остановка служб и принудительное извлечение могут не сработать." -ForegroundColor Yellow
        Write-Host "  Убери ключ -NoElevate или запусти через USB-Eject.bat — права запросятся сами." -ForegroundColor Yellow
    }

    $targets = @(Get-Targets)

    if ($List) { Show-Targets $targets; exit 0 }

    if ($Scan) {
        $l = if ($Drive) { [char]($Drive.TrimEnd(':', '\').Substring(0, 1).ToUpper()) } else { [char]'C' }
        Write-Host ""
        Write-Host "Сканирую открытые дескрипторы на диске $($l):\ ..." -ForegroundColor Cyan
        $dn = $null
        try { $dn = Get-Partition -DriveLetter $l -ErrorAction Stop | Select-Object -ExpandProperty DiskNumber -First 1 } catch {}
        $extra = @()
        if ($null -ne $dn) { $extra = @("\\.\PhysicalDrive$dn", "\Device\Harddisk$dn") }
        $res = Get-BlockingProcesses -Letter $l -ExtraPrefixes $extra
        Write-Host ""
        Show-Blockers -Procs $res.Processes
        Show-Verdict -Procs $res.Processes
        if ($res.Leaked -gt 0) { Write-Host "(пропущено зависших дескрипторов: $($res.Leaked))" -ForegroundColor DarkGray }
        exit 0
    }

    function Resolve-TargetByInput {
        param([string]$InputText, $Targets)
        $s = ([string]$InputText).Trim().TrimEnd(':', '\')
        if ($s.Length -eq 0) { return $null }
        $lc = [char]($s.Substring(0, 1).ToUpper())
        $t = $Targets | Where-Object { $_.Letter -eq $lc } | Select-Object -First 1
        if ($t) { return $t }
        $v = Get-Volume -DriveLetter $lc -ErrorAction SilentlyContinue
        if ($v) {
            $dn = $null
            try { $dn = Get-Partition -DriveLetter $lc -ErrorAction Stop | Select-Object -ExpandProperty DiskNumber -First 1 } catch {}
            $dev = $null
            if ($null -ne $dn) {
                $dev = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue) | Where-Object { $null -ne $_.Index -and [int]$_.Index -eq [int]$dn } | Select-Object -First 1
            }
            return [pscustomobject]@{
                Letter        = $lc
                Label         = $(if ($v.FileSystemLabel) { $v.FileSystemLabel } else { '(без метки)' })
                FS            = $v.FileSystem
                SizeGB        = [math]::Round($v.Size / 1GB, 1)
                Model         = '?'
                DiskNumber    = $dn
                InstanceId    = $(if ($dev) { $dev.PNPDeviceID } else { $null })
                PhysicalDrive = $(if ($null -ne $dn) { "\\.\PhysicalDrive$dn" } else { $null })
            }
        }
        return $null
    }

    # Выбор диска: неправильная буква -> переспрашиваем, пока не введёт существующую
    $sel = $Drive
    if (-not $sel) {
        Show-Targets $targets
        Write-Host ""
        $sel = Read-Host "Буква диска для извлечения (Enter = выход)"
    }
    $target = Resolve-TargetByInput -InputText $sel -Targets $targets
    while (-not $target) {
        Write-Host ""
        Write-Host "Диск '$($sel.Trim())' не найден или не подключён. Есть:" -ForegroundColor Red
        Show-Targets $targets
        Write-Host ""
        $sel = Read-Host "Введи букву диска ещё раз (Enter = выход)"
        if (-not $sel) { exit 0 }
        $target = Resolve-TargetByInput -InputText $sel -Targets $targets
    }
    $letter = $target.Letter

    if ($letter -eq 'C') {
        Write-Host "ВНИМАНИЕ: $($letter): — системный диск, извлечь его нельзя (это опасно)." -ForegroundColor Red
        $a = Read-Host "Продолжить всё равно? [y/N]"
        if ($a -notin @('y', 'д', 'да', 'yes')) { exit 0 }
    }

    foreach ($n in (Test-SpecialUse $letter)) { Write-Host "! $n" -ForegroundColor Yellow }

    Write-Host ""
    Write-Host ("Цель: {0}: «{1}»  [{2}]" -f $letter, $target.Label, $target.Model) -ForegroundColor Cyan

    $attempt = 0
    $ejectConfirmed = [bool]($Kill -or $Yes)
    while ($true) {
        $attempt++
        Write-Host ""
        Write-Host "--- Попытка $attempt ---" -ForegroundColor DarkCyan

        Write-Host "Сканирую открытые дескрипторы, ищу держателей..." -ForegroundColor Cyan
        $extra = @()
        if ($null -ne $target.DiskNumber) { $extra = @("\\.\PhysicalDrive$($target.DiskNumber)", "\Device\Harddisk$($target.DiskNumber)") }
        $res = Get-BlockingProcesses -Letter $letter -ExtraPrefixes $extra
        $procs = $res.Processes

        if ($procs.Count -gt 0) {
            Write-Host ""
            Show-Blockers -Procs $procs
            Show-Verdict -Procs $procs

            $actionable = @($procs | Where-Object { $_.Category -ne 'system' })
            if ($actionable.Count -gt 0) {
                if ($Kill -or $Yes) {
                    Write-Host ""
                    Write-Host "Режим -Kill/-Yes: останавливаю найденные программы и службы..." -ForegroundColor Cyan
                    Invoke-StopBlockers -Items $actionable
                } else {
                    Write-Host ""
                    $ans = Read-Host "  Что остановить? (номера через запятую | A - все, кроме системных | S - только службы | W - Проводник | Enter - ничего)"
                    $selected = @()
                    $wantSvc = $false
                    $wantExp = $false
                    foreach ($t in @(($ans -split '[,;\s]+' | Where-Object { $_ }))) {
                        $tu = $t.Trim().ToUpper()
                        if ($tu -eq 'A' -or $tu -eq 'А') { $selected = @($actionable); break }
                        elseif ($tu -eq 'S' -or $tu -eq 'С') { $wantSvc = $true }
                        elseif ($tu -eq 'W') { $wantExp = $true }
                        elseif ($tu -match '^\d+$') {
                            $m = @($actionable | Where-Object { $_.Num -eq ([int]$tu) })
                            if ($m.Count -gt 0) { $selected += $m }
                            else { Write-Host "  (пункт $tu не найден или это системный процесс)" -ForegroundColor DarkGray }
                        }
                    }
                    if ($wantSvc) { $selected += @($actionable | Where-Object { $_.Category -eq 'service' }) }
                    if ($wantExp) { $selected += @($actionable | Where-Object { $_.Category -eq 'explorer' }) }
                    $selected = @($selected | Sort-Object Pid -Unique)
                    if ($selected.Count -gt 0) {
                        Invoke-StopBlockers -Items $selected
                    } else {
                        Write-Host "  Ничего не останавливаю." -ForegroundColor DarkGray
                    }
                }
            } else {
                Write-Host ""
                Write-Host "  Держат только защищённые системные процессы — их не трогаем." -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "Явных блокирующих процессов не найдено (возможно, диск держит система/драйвер)." -ForegroundColor DarkGray
        }

        # Решение об извлечении — всегда за пользователем (кроме режима -Kill/-Yes)
        if (-not $ejectConfirmed) {
            $a = Read-Host "  Извлечь диск $($letter): сейчас? [Y = да / n = нет, оставить подключённым]"
            if ($a -in @('n', 'н', 'no', 'нет')) {
                Write-Host "Отменено: диск $($letter): остаётся подключённым." -ForegroundColor Yellow
                Restart-StoppedServices
                break
            }
            $ejectConfirmed = $true
        }

        $closed = Close-ExplorerWindows -Letter $letter
        if ($closed -gt 0) { Write-Host "Закрыто окон Проводника на диске $($letter): : $closed" -ForegroundColor Green }
        Start-Sleep -Milliseconds 300
        Write-Host "Пытаюсь извлечь устройство..." -ForegroundColor Cyan
        $vetoInfo = ''
        $err = [UsbEject.Native]::EjectDevice($letter, $target.InstanceId, $target.PhysicalDrive, [ref]$vetoInfo)
        if (-not $err) {
            Write-Host ""
            Write-Host ("[OK] Готово! Диск {0}: («{1}») безопасно извлечён — можно отсоединять." -f $letter, $target.Label) -ForegroundColor Green
            if ($vetoInfo) {
                Write-Host "Примечание: $vetoInfo" -ForegroundColor DarkYellow
                # Убираем PnP-узлы диска и контроллера, чтобы Windows не показывала
                # своё окно «устройство ещё используется» и узел не зависал при переподключении
                Write-Host "Отключаю устройство также на уровне PnP (чтобы не зависало при переподключении)..." -ForegroundColor DarkCyan
                $parent = $null
                try { $parent = (Get-PnpDeviceProperty -InstanceId $target.InstanceId -KeyName "DEVPKEY_Device_Parent" -ErrorAction Stop).Data } catch {}
                [void](Remove-DeviceNodeSilent -InstanceId $target.InstanceId)
                if ($parent) { [void](Remove-DeviceNodeSilent -InstanceId $parent) }
            }
            Restart-StoppedServices
            break
        }
        Write-Host "[!!] Не получилось: $err" -ForegroundColor Red
        if ($attempt -ge 3) {
            Write-Host "Подсказки: закройте программы из списка выше и открытые файлы с диска;" -ForegroundColor Yellow
            Write-Host "если ничего не помогает — перезайдите в Windows или перезагрузите ПК." -ForegroundColor Yellow
            break
        }
        $a = Read-Host "Повторить попытку? [Y/n]"
        if ($a -in @('n', 'н', 'no', 'нет')) {
            Restart-StoppedServices
            break
        }
    }
}
catch {
    Write-Host ""
    Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
finally {
    if (-not $NoPause) { try { [void](Read-Host "`nНажмите Enter для выхода") } catch {} }
}

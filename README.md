# NCSIOverride for Windows 11

**This fork of [dantmnf/NCSIOverride](https://github.com/dantmnf/NCSIOverride) for latest versions of Windows uses MinHook framework instead of Detours.**

----------------

Does Windows keep saying NO INTERNET CONNECTION despite you are searching for this right now, on this very PC?

*This is ~~not~~ for you.*

## Notes

* Npcap (bundled with Wireshark / Nmap) is known to break NCSI.
* You can trigger a NCSI reprobe by disabling and enabling a random network adapter.

## Installation

1. Download from [Releases](https://github.com/shezik/NCSIOverride/releases)
2. Copy `NCSIOverride.dll` into `%SystemRoot%\System32`
3. Configure `Install.reg` and import it

## Configuration

Configuartion is stored in `HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride`, see [`Install.reg`](Install.reg) for example

    NCSIOverride
    | # Set default override for all interfaces here
    | DefaultOverrideV4 REG_DWORD
    | DefaultOverrideV6 REG_DWORD
    +-InterfaceOverride
    | +-{INTERFACE-GUID}
    |   | # Set override for interface with specified GUID here, overwriting DefaultOverride
    |   | OverrideV4      REG_DWORD
    |   \ OverrideV6      REG_DWORD
    +-Offsets
      | # Offset to SetCapability function in ncsi.dll
      | # Will stop working if the value is outdated
      \ NCSI_INTERFACE_ATTRIBUTES_SetCapability REG_QWORD


Values for `DefaultOverrideV4`, `DefaultOverrideV6`, `OverrideV4`, `OverrideV6`:
| Value |  Action  |
|-------|----------|
|   0   | None     |
|   1   | Local    |
|   2   | Internet |
|   3   | Max [*(Wtf?)*](https://github.com/dantmnf/NCSIOverride/issues/5#issuecomment-1368259131) |


`{INTERFACE-GUID}` can be obtained through:

    PS C:\> Get-NetAdapter | select Name, InterfaceGuid

    Name       InterfaceGuid                         
    ----       -------------                         
    Ethernet 2 {640470cf-5b79-4df2-b462-5648463881d9}
    Wi-Fi      {4efa6faf-9a7c-47bc-8179-6dc85adc9a59}


With [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) installed, the function offset can be updated by running [`Update-Offset.ps1`](Update-Offset.ps1) as administrator, or manually obtained using WinDbg:

    C:\Program Files (x86)\Windows Kits\10\Debuggers\x64>windbg rundll32.exe ncsi.dll,NcsiPerformReprobe
    # in WinDbg command window
    0:000> sxe ld:ncsi.dll
    0:000> g
    0:000> ? ncsi!NCSI_INTERFACE_ATTRIBUTES::SetCapability - ncsi
    Evaluate expression: 107868 = 00000000`0001a55c

## Building

First, build [MinHook](https://github.com/TsudaKageyu/minhook) and place `libMinHook.x??.lib` and `MinHook.h` into `MinHook` directory under project root.

You need MSVC or Clang with MSVC ABI to build this project.

## Notes

* Current implementation sets the override passively by changing parameter in function call. You need to trigger a reprobe to reflect changed override value.
* This can't override physically disconnected interface. 

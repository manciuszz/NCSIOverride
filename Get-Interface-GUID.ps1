Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Get-NetAdapter | select Name, InterfaceGuid

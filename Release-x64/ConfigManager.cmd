<# :
  @echo off
    powershell /nologo /noprofile /command ^
        "&{[ScriptBlock]::Create((cat """%~f0""") -join [Char[]]10).Invoke(@(&{$args}%*))}"
  exit /b
#>

Function Override-Probe {
	param(
		[Parameter(Mandatory=$true)]
		[boolean]$Enabled
	)
	
	if (-not [System.Environment]::Is64BitOperatingSystem) {
		Write-Host "Non 64-bit systems are not supported."
		return
	}
	
	Function ForEach-Interface-GUID {
		param (
			[Parameter(Mandatory=$true)]
			[ScriptBlock]$Callback
		)

		$adapters = Get-NetAdapter | Select-Object -Property Name, InterfaceGuid
		foreach ($adapter in $adapters) {
			& $Callback $adapter.InterfaceGuid
		}
	}

	Function Update-Offset {
		try {
			$output = "
				* enable loading symbol from Microsoft symbol server
				.sympath srv*
				* set breakpoint on loading ncsi.dll
				sxe ld:ncsi.dll
				* run debuggee and wait for the module loading breakpoint
				g
				* resolve function offset from symbol
				? ncsi!NCSI_INTERFACE_ATTRIBUTES::SetCapability - ncsi
				* exit debugger
				q
			" | & .\binaries\cdb.exe "rundll32.exe" "ncsi.dll,NcsiPerformReprobe" | Select-String -Pattern "Evaluate expression: (\d+)"

			$offset = [long]$output.Matches[0].Groups[1].Value
			Write-Output ("Function offset: 0x{0:x}" -f $offset)

			New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\Offsets" -Force
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\Offsets" -Name "NCSI_INTERFACE_ATTRIBUTES_SetCapability" -Value $offset -Type Qword -Force
			
			Write-Host "Successfully set the offset value in registry."
		} catch {
			Write-Host "Failed to set the offset value in registry. Uninstalling."
			Uninstall
		}
	}
	
	Function Manage-Binaries([boolean]$Install) {
		$NCSIOverrideDLL = "NCSIOverride.dll"
		
		$BINARY_DIRECTORY = Get-Location | Select -ExpandProperty Path
		$BINARY_PATH = Join-Path -Path $BINARY_DIRECTORY -ChildPath $NCSIOverrideDLL
		$SYSTEM_PATH = Join-Path -Path $ENV:SystemRoot -ChildPath "System32" | Join-Path -ChildPath $NCSIOverrideDLL
		
		Function Validate {
			return Test-Path $SYSTEM_PATH
		}
		
		Function Install {
			if (-not (Test-Path -Path $BINARY_PATH)) {
				Write-Host "$NCSIOverrideDLL could not be found in '$BINARY_PATH'"
				return $false
			}
			
			if (Validate) {
				Write-Host "$NCSIOverrideDLL was already installed."
				return $true
			}
			
			Copy-Item -Path $BINARY_PATH -Destination $SYSTEM_PATH
			Write-Host "$NCSIOverrideDLL binary was installed."
			return $true
		}
		
		Function Uninstall {
			if (-not (Validate)) {
				return
			}
			
			try {
				Remove-Item -Path $SYSTEM_PATH
			} catch {
				try {
					Stop-Service -Name "netprofm" -Force -Confirm:$false
				} catch {
					$svcPid = Get-WMIObject Win32_service | where Started -eq "True" | where Name -eq "netprofm" | select ProcessId
					$process = Get-Process -Id $svcPid.ProcessId
					$process.Kill()
				}
			} finally {
				Remove-Item -Path $SYSTEM_PATH -ErrorAction SilentlyContinue | Out-Null
			}
		}
		
		if ($Install) {
			return Install
		} else {
			return Uninstall
		}
	}
	
	Function Install {
		Function CheckIfNotAlreadyInstalled {
			return Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride"
		}
		
		Function Hook-Library-ToRegistry {
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netprofm\Parameters" -Name "ServiceDll" -Value "%SystemRoot%\System32\NCSIOverride.dll" -Type ExpandString -Force
		}
		
		Function Setup-Default-Override {
			New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride" -Force
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride" -Name "DefaultOverrideV4" -Value 0 -Type Dword -Force
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride" -Name "DefaultOverrideV6" -Value 0 -Type Dword -Force
		}
		
		Function Setup-Interface-Override {
			New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\InterfaceOverride" -Force
		
			ForEach-Interface-GUID {
			  param($InterfaceGuid)
			  
			  New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\InterfaceOverride\$InterfaceGuid" -Force
			  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\InterfaceOverride\$InterfaceGuid" -Name "OverrideV4" -Value 2 -Type Dword -Force
			  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride\InterfaceOverride\$InterfaceGuid" -Name "OverrideV6" -Value 2 -Type Dword -Force
			}
		}
		
		if (CheckIfNotAlreadyInstalled) {
			Write-Host "NCSI-Override was already installed."
			return
		}
		
		if (-not (Manage-Binaries -Install $true)) {
			return
		}
		
		Hook-Library-ToRegistry	 
		Setup-Default-Override
		Setup-Interface-Override
		Update-Offset
		
		Write-Host "NCSI-Override installed successfully"
	}
	
	Function Uninstall {
		Manage-Binaries -Install $false
		
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\NCSIOverride" -Force -Recurse -Confirm:$false
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netprofm\Parameters" -Name "ServiceDll" -Value "%SystemRoot%\System32\netprofmsvc.dll" -Type ExpandString -Force
		
		Write-Host "NCSI-Override has been uninstalled successfully"
	}
	
	if ($Enabled) {
		Install
	} else {
		Uninstall
	}
}

if ($args[0]) {
	switch($args[0]) {
		"Install" {
			Override-Probe -Enabled  $true | Out-Null
		}
		"Uninstall" {
			Override-Probe -Enabled $false | Out-Null
		}
	}
}
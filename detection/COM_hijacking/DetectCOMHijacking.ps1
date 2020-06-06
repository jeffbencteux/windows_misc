function Key-ValueDiff ($HKCU_key_path, $HKCU_property_name, $check_empty_keys)
{
	if (!(Test-Path "Registry::$HKCU_key_path"))
	{
		Write-Output "Asked key does not exists"
		return
	}
	
	$HKCU_subkeys = Get-ChildItem -path "Registry::$HKCU_key_path"
	
	foreach ($HKCU_subkey in $HKCU_subkeys) {
		if (${HKCU_subkey}.Name -like "*$HKCU_property_name*")
			{
				$HKCU_found_property_name = (Get-Item -path "Registry::${HKCU_subkey}") | Split-Path -leaf
				$HKCU_value = (Get-Item -path "Registry::${HKCU_subkey}").GetValue("")
				
				if ($HKCU_value -eq "")
				{
					continue
				}
				
				$HKLM_CLSID_key_name = $HKCU_CLSID_key.Name -replace "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"
			
				# Check if there is the same key in HKLM
				if (!(Test-Path "Registry::$HKLM_CLSID_key_name"))
				{
					if ($check_empty_keys)
					{
						Write-Output "Key values differs in HKLM and HKCU:`n"
						Write-Output "Key path: $HKCU_key_path"
						Write-Output "Key property name: $HKCU_found_property_name"
						Write-Output "HKLM: EMPTY"
						Write-Output "HKCU: $HKCU_value`n"
					}
					continue
				}
					
				$HKLM_subkeys = Get-ChildItem -path "Registry::$HKLM_CLSID_key_name"
					
				foreach ($HKLM_subkey in $HKLM_subkeys) {
					if (${HKLM_subkey}.Name -like "*$HKCU_property_name*")
					{
						# Check if the HKLM and HKCU keys have different values
						$HKLM_value = (Get-Item -path "Registry::${HKLM_subkey}").GetValue("")
						$HKCU_value = (Get-Item -path "Registry::${HKCU_subkey}").GetValue("")
						
						if ($HKLM_value -ne $HKCU_value)
						{
							Write-Output "Key values differs in HKLM and HKCU:`n"
							Write-Output "Key path: $HKCU_key_path"
							Write-Output "Key property name: $HKCU_found_property_name"
							Write-Output "HKLM: $HKLM_value"
							Write-Output "HKCU: $HKCU_value`n"
						}
					}
				}
			}
	}
}

function Key-IsPropertyPresent ($key, $property)
{
	if (Test-Path "Registry::$key\$property")
	{
		$property_value = (Get-Item -path "Registry::$key\$property").GetValue("")
		Write-Output "$property found:`n"
		Write-Output "Key: $key"
		Write-Output "${property}: $property_value`n"
	}
}

function Detect-COMHijacking
{
<#
.SYNOPSIS
Check for COM hijacking in registry
.DESCRIPTION
Several COM hijacking techniques involve the override of HKLM registry keys with
HKCU keys, these having precedence. An attacker would change the value of a 
property of a registry key in HKCU or create that key and the associated 
property in that hive. Other properties allow an attacker to replace the COM 
class location, to impersonate the class or to redirect to an arbitrary script
by adding a key that did not exists in HKLM.
 
These techniques can be detected by checking the registry for such changes. This
is what this script does. It checks for differences in registry keys properties
between HKLM and HKCU hives or simply check for the presence of some of these
properties.
.PARAMETER CheckEmptyKeys
Wether to check for differences when HKCU has a value but HKLM is empty
#>
	[CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false)]
        [switch]$CheckEmptyKeys=$false
    )

	$HKLM_CLSID = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\Classes\CLSID"
	$HKCU_CLSID = Get-ChildItem -Path "Registry::HKCU\SOFTWARE\Classes\CLSID"

	$HKLM_COM_classes_count = ($HKLM_CLSID | Measure-Object).Count
	$HKCU_COM_classes_count = ($HKCU_CLSID | Measure-Object).Count
	Write-Output "Checking $HKLM_COM_classes_count COM classes registered in HKLM and $HKCU_COM_classes_count in HKCU`n"

	# HKCU precedence replacement technique
	foreach ($HKCU_CLSID_key in $HKCU_CLSID) {
		Key-ValueDiff ${HKCU_CLSID_key} "InprocServer" $CheckEmptyKeys
		Key-ValueDiff $HKCU_CLSID_key "LocalServer" $CheckEmptyKeys
		Key-ValueDiff $HKCU_CLSID_key "ProgID" $CheckEmptyKeys
	}

	# Whatever unusal and rare enough properties used for hijacking are reported
	foreach ($HKCU_CLSID_key in $HKCU_CLSID) {
		Key-IsPropertyPresent $HKCU_CLSID_key "ScriptletURL"
		Key-IsPropertyPresent $HKCU_CLSID_key "TreatAs"
	}
}

# Export-ModuleMember -Function "Detect-COMHijacking"


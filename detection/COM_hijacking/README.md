Author: Jeffrey Bencteux

# What is it?

A small powershell script to detect (some) COM classes hijacking techniques.

# What does it do?

## TL;DR;

* Find non-matching key values for InprocServer32, LocalServer32 and ProgID 
  properties between HKLM and HKCU registered COM classes
* Find values for ScriptletURL and TreatAs property in registered COM classes 
  in HKCU

## Detecting COM hijacking techniques with registry checks

COM class hijacking is a known technique to achieve persistence on Windows.

Several COM hijacking techniques involve the override of HKLM registry keys with
 HKCU keys, these having precedence. An attacker would change the value of a 
 property of a registry key in HKCU or create that key and the associated 
 property in that hive. Other properties allow an attacker to replace the COM 
 class location, to impersonate the class or to redirect to an arbitrary script
 by adding a key that did not exists in HKLM. These techniques have been found
 in the work in reference.
 
These techniques can be detected by checking the registry for such changes. This
 is what this script does. It checks for differences in registry keys properties
 between HKLM and HKCU hives or simply check for the presence of some of these
 properties.
 
Here are the currently supported techniques this script detects:
 
* the replacement/addition in HKCU of the value of InprocServer/InprocServer32
  properties with a malicious DLL.
* the replacement/addition in HKCU of the value of LocalServer/LocalServer32 
  properties with a malicious EXE.
* the replacement/addition in HKCU of the value of ProgID property with a 
  malicious ID.
* the presence in HKCU of the value of ScriptletURL property
* the presence in HKCU of the value of TreatAs property

False positives can occurs and having results does not mean being hijacked. 
Output of the script must be reviewed and checked.

Having a value in HKCU while HKLM equivalent key is empty is common on a Windows
 system. The verification of empty HKLM keys is optional in the script.

# Examples

```
PS C:\Users\jeff\Documents\com_hijacking> Import-Module .\DetectCOMHijacking.ps1
PS C:\Users\jeff\Documents\com_hijacking> Detect-COMHijacking
Checking 7272 COM classes registered in HKLM and 22 in HKCU

Key values differs in HKLM and HKCU:

Key path: HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{603D3801-BD81-11d0-A3A5-00C04FD706EC}
Key property name: InprocServer32
HKLM: C:\WINDOWS\system32\windows.storage.dll
HKCU: C:\TEMP\pwned.dll

ScriptletURL found:

Key: HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\TEST
ScriptletURL: http://localhost/test.sct

PS C:\Users\jeff\Documents\com_hijacking>
```

With empty HKLM keys switch on:

```
PS C:\Users\jeff\Documents\com_hijacking> Detect-COMHijacking -CheckEmptyKeys
Checking 7272 COM classes registered in HKLM and 22 in HKCU

Key values differs in HKLM and HKCU:

Key path: HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}
Key property name: InProcServer32
HKLM: EMPTY
HKCU: C:\WINDOWS\system32\shell32.dll

Key values differs in HKLM and HKCU:

Key path: HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{021E4F06-9DCC-49AD-88CF-ECC2DA314C8A}
Key property name: LocalServer32
HKLM: EMPTY
HKCU: C:\Users\jeff\AppData\Local\Microsoft\OneDrive\20.064.0329.0008\FileCoAuth.exe
...
```

# References

* [Persistence – COM Hijacking, pentestlab.blog](https://pentestlab.blog/2020/05/20/persistence-com-hijacking/)
* [COM Hijacking Techniques - Derbycon 2019, David Tulis](https://www.slideshare.net/DavidTulis1/com-hijacking-techniques-derbycon-2019)
* [acCOMplice tool, David Tulis](https://github.com/nccgroup/acCOMplice)

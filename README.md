# Windows 10 Privacy Fixup

Fixes Windows 10 settings to be more privacy oriented and removes bloat.
This script is mainly used for VMs and slimline PCs.
This WILL break some things (as it should), you have been warned.

This disables/breaks:

- Telemetry
- Internet Explorer
- Most WIndows Apps (except Store)
- Cortana/Search
- Delivery Optimization
- OneDrive
= Sync
- Defrag
- Themes
- Windows Defender
- Windows Firewall
- Sleep/Suspend (Hibernate is Ok!)
- Fax and XPS
- Workfolders
- SMB Host (v1 and v2)

Enables the Linux Subsystem!

## How to run

Download the script from here or ```dij.sh/win10``` [Link](https://dij.sh/win10)

Run the following command:

```[powershell]
powershell -ExecutionPolicy Unrestricted -File Fixup.ps1
```

- or -

```[powershell]
powershell -ExecutionPolicy Unrestricted -Command "Invoke-WebRequest -UseBasicParsing 'https://dij.sh/win10' | Invoke-Expression"
```

The script will prompt for UAC when needed.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z4121TDS)

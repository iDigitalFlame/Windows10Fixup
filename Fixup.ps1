#!/usr/bin/pwsh
# iDigitalFlame
#  Fix everything wrong with Windows 10.
#  Warning, this will break ALOT of things in Windows (like Edge), so be warned.
#
# Copyright (C) 2020 - 2022 iDigitalFlame
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

$IsAdjusted = $false
$InvokeURL = "https://dij.sh/win10"
$ErrorActionPreference = "SilentlyContinue"
$InvokeMe = "-NoProfile -ExecutionPolicy Unrestricted -File `"$PSCommandPath`""
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

If ($PSCommandPath.length -eq 0) {
    $InvokeMe = "-NoProfile -ExecutionPolicy Unrestricted -Command `"Invoke-WebRequest -UseBasicParsing '$($InvokeURL)' | Invoke-Expression`""
}

function mkdir($dir) {
    if (Test-Path $dir) {
        return
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
function adjustPrivs {
    if (!$IsAdmin -or $IsAdjusted) {
        return
    }
    $def = @'
using System;
using System.Runtime.InteropServices;

public class AddPrivs
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
      public int Count;
      public long Luid;
      public int Attr;
    }

    public static bool EnablePrivilege(long processHandle, string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = new IntPtr(processHandle);
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, 0x00000020|0x00000008, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = 0x00000002;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
    }
}
'@
    $h = (Get-Process -id $pid).Handle
    $t = Add-Type $def -PassThru
    $IsAdjusted = $t[0]::EnablePrivilege($h, "SeTakeOwnershipPrivilege")
}
function TaskSettings() {
    Write-Host -ForegroundColor Cyan "Removing un-needed Tasks ..."
    Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "QueueReporting" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "GoogleUpdateTaskMachineCore" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "GoogleUpdateTaskMachineUA" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "OfficeTelemetryAgentFallBack2016" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "OfficeTelemetryAgentLogOn2016" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\AppID\SmartScreenSpecific" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Bluetooth\UninstallDeviceTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Clip\License Validation" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Device Setup\Metadata Refresh" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Diagnosis\Scheduled" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\DiskFootprint\Diagnostics" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\DiskFootprint\StorageSense" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\FileHistory\File History (maintenance mode)" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\LanguageComponentsInstaller\Installation" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Location\Notifications" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Location\WindowsActionDialog" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Maps\MapsToastTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\MUI\LPRemove" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Multimedia\SystemSoundsService" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\NetTrace\GatherNetworkInfo" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Offline Files\Background Synchronization" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Offline Files\Logon Synchronization" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Ras\MobilityManager" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\SettingSync\BackgroundUploadTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\SettingSync\NetworkStateChangeTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Shell\FamilySafetyMonitor" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Shell\FamilySafetyRefresh" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\SpacePort\SpaceAgentTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Sysmain\HybridDriveCacheRebalance" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\SystemRestore\SR" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Time Zone\SynchronizeTimeZone" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\TPM\Tpm-HASCertRetr" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\TPM\Tpm-Maintenance" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\UPnP\UPnPHostConfig" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\WCM\WiFiTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\WDI\ResolutionHost" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\WindowsColorSystem\Calibration Loader" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Wininet\CacheTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Workplace Join\Automatic-Device-Join" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\WS\License Validation" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\WS\WSTask" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Maintenance\WinSAT" | Out-Null
    Disable-ScheduledTask -ErrorAction SilentlyContinue -TaskName "Microsoft\Windows\Device Information\Device" | Out-Null
}
function PowerSettings() {
    Write-Host -ForegroundColor Cyan "Adding better power and disk settings..."
    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue | Out-Null
    Disable-MMAgent -ApplicationPreLaunch -ErrorAction SilentlyContinue | Out-Null
    fsutil behavior set DisableLastAccess 1 | Out-Null
    fsutil behavior set EncryptPagingFile 0 | Out-Null
    powercfg /X monitor-timeout-ac 0 | Out-Null
    powercfg /X monitor-timeout-dc 0 | Out-Null
    powercfg /X standby-timeout-ac 0 | Out-Null
    powercfg /X standby-timeout-dc 0 | Out-Null
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
}
function FolderSettings() {
    Write-Host -ForegroundColor Cyan "Removing un-needed user directories..."
    Remove-Item -ErrorAction SilentlyContinue -Force "$($env:USERPROFILE)\Desktop\Microsoft edge.lnk" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\3D Objects" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Contacts" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Favorites" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Pictures" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\MicrosoftEdgeBackups" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Music" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Saved Games" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Searches" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse "$($env:USERPROFILE)\Videos" | Out-Null
}
function PackageSettings() {
    Write-Host -ForegroundColor Cyan "Removing un-needed AppX Packages..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.GamingServices" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "king.com.*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    Get-AppxPackage | where-Object { !$_.Publisher.Contains("CN=Microsoft ") } | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    $p = @(
        "Feedback"
        "Flash"
        "Gaming"
        "Holo"
        "Maps"
        "MiracastView"
        "OneDrive"
        "Wallet"
    )
    Foreach ($i in $p) {
        $m = (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" | Where-Object Name -Like "*$i*")
        Foreach ($n in $m) {
            Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:$($n.Name.Substring(18))" -Name "Visibility" -Value 1 | Out-Null
            New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:$($n.Name.Substring(18))" -Name "DefVis" -PropertyType DWord -Value 2 | Out-Null
            Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:$($n.Name.Substring(18))\Owners" | Out-Null
            dism.exe /Online /Remove-Package /PackageName:$($n.Name.split('\')[-1]) /NoRestart | Out-Null
        }
    }
    If ($IsAdmin) {
        Write-Host -ForegroundColor Cyan "Removing un-needed AppX Packages (AllUsers)..."
        Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.AppConnector" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingFinance" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingNews" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingSports" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingTranslator" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingWeather" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.BingTravel" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.GamingServices" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.GetHelp" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Getstarted" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.FreshPaint" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Messaging" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.ScreenSketch" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.MSPaint" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.OneConnect" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.People" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Print3D" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Wallet" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "microsoft.windowscommunicationsapps" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.YourPhone" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "2414FC7A.Viber" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "64885BlueEdge.OneCalendar" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "7EE7776C.LinkedInforWindows" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "CAF9E577.Plex" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Facebook.Facebook" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "SpotifyAB.SpotifyMusic" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "WinZipComputing.WinZipUniversal" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "XINGAG.XING" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "king.com.*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.XboxApp" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers | where-Object { !$_.Publisher.Contains("CN=Microsoft ") } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
    }
}
function NetworkSettings() {
    Write-Host -ForegroundColor Cyan "Disabling un-needed network settings..."
    Enable-NetFirewallRule -Name "RemoteDesktop*" -ErrorAction SilentlyContinue | Out-Null
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp" -ErrorAction SilentlyContinue | Out-Null
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio" -ErrorAction SilentlyContinue | Out-Null
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr" -ErrorAction SilentlyContinue | Out-Null
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue | Out-Null
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
}
function FeatureSettings() {
    Write-Host -ForegroundColor Cyan "Disabling un-needed Features..."
    Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Enable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Microsoft-Windows-Subsystem-Linux" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Printing-Foundation-Features" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "FaxServicesClientPackage" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Printing-Foundation-InternetPrinting-Client" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "WindowsMediaPlayer" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "WorkFolders-Client" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "SearchEngine-Client-Package" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Printing-XPSServices-Features" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Printing-PrintToPDFServices-Features" | Out-Null
    Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction SilentlyContinue -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("App.Support.QuickAssist") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Browser.InternetExplorer") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Hello.Face.") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Language.Handwriting") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Language.OCR") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Language.Speech") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Language.TextToSpeech") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("MathRecognizer") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Microsoft.Windows.PowerShell.ISE") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Microsoft.Windows.WordPad") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("OneCoreUAP.OneSync") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Get-WindowsCapability -Online | Where-Object { $_.Name.Contains("Print.Fax.Scan") } | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null
    Remove-Printer -ErrorAction SilentlyContinue -Name "Fax" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Quick Assist.lnk" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows Fax and Scan.lnk" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Wordpad.lnk" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "C:\Programdata\Microsoft\Windows\Start Menu\Programs\MiracastView.lnk" | Out-Null
    Start-Process -Wait -FilePath "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\setup.exe" -ArgumentList @("--uninstall", "--system-level", "--force-uninstall") -ErrorAction SilentlyContinue | Out-Null
}
function ServiceSettings() {
    Write-Host -ForegroundColor Cyan "Disabling un-needed Services..."
    Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ALG" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Bonjour Service" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SharedRealitySvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TapiSvr" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wmiApSrv" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AssignedAccessManagerSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "bthserv" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DevQueryBroker" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "embeddedmode" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WFDSConMgrSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PushToInstall" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "spectrum" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "diagsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "NcaSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "NcdAutoSetup" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "lltdsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SecurityHealthService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "EntAppSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    # NOTE(dij): Breaks Windows Update
    Set-Service "AppReadiness" -StartupType Manual -ErrorAction SilentlyContinue | Out-Null
    Set-Service "CDPSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "BthAvctpSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AudioEndpointBuilder" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wsappx" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AppVClient" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "autotimesvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AxInstSV" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "BcastDVRUserService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "BDESVC" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "BTAGService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "BluetoothUserService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "CaptureService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "CDPUserSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ClipSVC" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "CscService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "defragsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DoSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DsSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DusmSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "EFS" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Fax" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "fdPHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "FDResPub" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "fhsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "FrameServer" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "icssvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "MapsBroker" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "MessagingService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "mpssvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "MSiSCSI" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "NaturalAuthentication" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "OneSyncSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "p2ppimsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "p2pimsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "p2psvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PcaSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PeerDistSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "perceptionsimulation" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PhoneSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PerfHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PNRPAutoReg" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "PNRPSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "QWAVE" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RasMan" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RemoteAccess" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RetailDemo" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RmSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SCardSvr" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ScDeviceEnum" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SCPolicySvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SDRSVC" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SEMgrSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SecurityHealthService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Sense" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SensorDataService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SensorService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SharedAccess" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "smphost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SmsRouter" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SNMPTRAP" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SSDPSRV" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ssh-agent" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TabletInputService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Themes" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TokenBroker" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TroubleshootingSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "UevAgentService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "upnphost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "VacSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "VSS" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WarpJITSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WalletService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wcncsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WdiServiceHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WdiSystemHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WebClient" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WEPHOSTSVC" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wercplsupport" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "workfolderssvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null #ne
    Set-Service "WpcMonSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WpnService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WpnUserService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblGamesave" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XboxGipSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null # ne
    Set-Service "XboxNetApiSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AJRouter" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ndu" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TrkWks" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wscsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WbioSrvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Audiosrv" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "MapsBroker" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblGameSave" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RemoteAccess" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WMPNetworkSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XboxNetApiSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "HomeGroupListener" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "HomeGroupProvider" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "NetTcpPortSharing" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
}
function OneDriveSettings() {
    Write-Host -ForegroundColor Cyan "Removing OneDrive..."
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 2
    $od = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $od)) {
        $od = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    if (Test-Path $od) {
        Start-Process $od "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Sleep -s 2
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -s 2
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "$env:USERPROFILE\OneDrive" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" | Out-Null
    foreach ($i in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
        Remove-Item -ErrorAction SilentlyContinue -Force -Recurse $i.FullName | Out-Null
    }
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse | Out-Null
    mkdir "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    mkdir "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    takeown "ClassesRoot" "CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    takeown "ClassesRoot" "Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKU:\Default\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" | Out-Null
}
function takeown($root, $key) {
    adjustPrivs
    $k = [Microsoft.Win32.Registry]::$root.OpenSubKey($key, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $a = $k1.GetAccessControl()
    $r = New-Object System.Security.AccessControl.RegistryAccessRule(".\$($env:UserName)", "FullControl", "Allow")
    $a.SetAccessRule($r)
    $k.SetAccessControl($a)
}
function RegistrySettings($IsAdmin) {
    Write-Host -ForegroundColor Cyan "Adding privacy settings in registry..."
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"
    mkdir "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\CredUI"
    mkdir "HKLM:\Software\Policies\Microsoft\MRT"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\SettingSync"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
    mkdir "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    mkdir "HKLM:\Software\Policies\Microsoft\PushToInstall"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\SmartGlass"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
    mkdir "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\ABCH"
    mkdir "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\ABCH-SKYPE"
    mkdir "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\FACEBOOK"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\AppHost"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds"
    mkdir "HKLM:\System\CurrentControlSet\Services\DiagTrack"
    mkdir "HKLM:\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service"
    mkdir "HKLM:\System\CurrentControlSet\Services\dmwappushservice"
    mkdir "HKLM:\System\CurrentControlSet\Services\DoSvc"
    mkdir "HKLM:\System\CurrentControlSet\Services\lfsvc"
    mkdir "HKLM:\System\CurrentControlSet\Services\WbioSrvc"
    mkdir "HKLM:\System\CurrentControlSet\Services\WSearch"
    mkdir "HKLM:\Software\Policies\Microsoft\Edge"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Onedrive"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote"
    mkdir "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings"
    mkdir "HKLM:\Software\Policies\Microsoft\Biometrics"
    mkdir "HKLM:\System\CurrentControlSet\Services\SysMain"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\System"
    mkdir "HKLM:\Software\Microsoft\Dfrg\BootOptimizeFunction"
    mkdir "HKLM:\System\CurrentControlSet\Control\CrashControl"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\OOBE"
    mkdir "HKLM:\Software\Microsoft\Windows Defender Security Center\Virus and threat protection"
    mkdir "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Notifications\Data"
    mkdir "HKLM:\Software\Policies\Google\Chrome"
    mkdir "HKLM:\Software\Policies\Microsoft\Edge"
    mkdir "HKLM:\Software\Policies\Mozilla\Firefox"
    mkdir "HKLM:\Software\Microsoft\EdgeUpdate"
    mkdir "HKLM:\Software\WOW6432Node\Microsoft\EdgeUpdate"
    mkdir "HKLM:\Software\Policies\Microsoft\WMDRM"
    mkdir "HKLM:\Software\Microsoft\WlanSvc\AnqpCache"
    mkdir "HKLM:\Software\Policies\Microsoft\AppV\CEIP"
    mkdir "HKLM:\Software\Policies\Microsoft\WindowsStore"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\System"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\GameDVR"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\TabletPC"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\SQMClient\Windows"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main"
    mkdir "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"
    mkdir "HKLM:\System\CurrentControlSet\Control\NetworkProvider"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Addons"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    mkdir "HKLM:\Software\Policies\Microsoft\InputPersonalization"
    mkdir "HKLM:\Software\Microsoft\Windows\Windows Error Reporting"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
    mkdir "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization"
    mkdir "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput"
    mkdir "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration"
    mkdir "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device”
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    mkdir "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    mkdir "HKLM:\Software\Wow6432Node\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder"
    mkdir "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    mkdir "HKLM:\Software\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder"
    mkdir "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    mkdir "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\FACEBOOK"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH-SKYPE"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"
    takeown "ClassesRoot" "CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    takeown "ClassesRoot" "CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}"
    takeown "ClassesRoot" "CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
    takeown "LocalMachine" "Software\Wow6432Node\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
    takeown "LocalMachine" "Software\Wow6432Node\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}"
    takeown "LocalMachine" "Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    takeown "LocalMachine" "Software\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
    ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
        New-Item -ErrorAction SilentlyContinue -Force -Path $("HKCR:\$type\shell\open") | Out-Null
        New-Item -ErrorAction SilentlyContinue -Force -Path $("HKCR:\$type\shell\open\command") | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" | Out-Null
    }
    Set-Item "HKLM:\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" "" | Out-Null
    New-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device” -Name "DevicePasswordLessBuildVersion" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\WOW6432Node\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Network" -Name "NewNetworkWindowOff" -Type DWord -Value 0xB0940064 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xA0100000 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xB0940064 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shell\cmd" -Name "ShowBasedOnVelocityId" -Type DWord -Value 0x639bc8 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shell\cmdprompt" -Name "NoWorkingDirectory" -Type String -Value "" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shell\cmdprompt" -Name "(Default)" -Type String -Value "@shell32.dll,-8506" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shell\cmdprompt" -Name "(Default)" -Type String -Value 'cmd.exe /s /k pushd "%V"' | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\cmd" -Name "ShowBasedOnVelocityId" -Type DWord -Value 0x639bc8 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\cmdprompt" -Name "NoWorkingDirectory" -Type String -Value "" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\cmdprompt" -Name "(Default)" -Type String -Value "@shell32.dll,-8506" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\cmdprompt\command" -Name "(Default)" -Type String -Value 'cmd.exe /s /k pushd "%V"' | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\PowerShell" -Name "ShowBasedOnVelocityId" -Type DWord -Value 0x639bc8 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Drive\shell\cmdprompt" -Name "NoWorkingDirectory" -Type String -Value "" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Drive\shell\cmdprompt" -Name "(Default)" -Type String -Value "@shell32.dll,-8506" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Drive\shell\cmdprompt\command" -Name "(Default)" -Type String -Value 'cmd.exe /s /k pushd "%V"' | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseOpen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" -Name "WiFiSenseCredShared" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" -Name "WiFiSenseOpen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "DiagTrackAuthorization" -Type DWord -Value 7 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SpecialRoamingOverrideAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Type String -Value "hide:appsfeatures;appsforwebsites;autoplay;backup;clipboard;cortana;cortana-language;cortana-moredetails;cortana-permissions;cortana-windowssearch;crossdevice;datausage;delivery-optimization;extras;findmydevice;fonts;maps;mobile-devices;network-cellular;network-dialup;network-directaccess;network-mobilehotspot;network-proxy;network-status;network-vpn;nfctransactions;otherusers;pen;privacy-accountinfo;privacy-activityhistory;privacy-backgroundapps;privacy-calendar;privacy-callhistory;privacy-contacts;privacy-customdevices;privacy-email;privacy-feedback;privacy-general;privacy-location;privacy-messaging;privacy-motion;privacy-radios;privacy-speech;privacy-speechtyping;quiethours;recovery;regionlanguage;remotedesktop;search;search-moredetails;storagesense;sync;themes;troubleshoot;usb;workplace;privacy-documents;privacy-videos;privacy-pictures;privacy-appdiagnostics;privacy-phonecalls;privacy-notifications;privacy-voiceactivation;privacy-tasks;privacy-automaticfiledownloads;project;developers;search-permissions;powersleep;windowsdefender;signinoptions;emailandaccounts;tabletmode;network;speech;" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WlanSvc\AnqpCache" -Name "OsuRegistrationStatus" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type String -Value "0" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type String -Value "0" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type String -Value "0" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xB0940064 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xA0100000 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableFileSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableMeteredNetworkFileSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\FACEBOOK" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH-SKYPE" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118" -Name "FeatureStates" -Type DWord -Value 381 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote" -Name "Type" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\NetworkProvider" -Name "RestoreConnection" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\Sense" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\Sense" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    # NOTE(dij): Apperently disabling these services fuck up the ability for Windows to download apps or updates.
    #            That's not good!
    #
    #   Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WdNisSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    #   Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WdNisSvc" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    #   Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\wscsvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    #   Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\mpssvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\PcaSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type String -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "DiagTrackAuthorization" -Type DWord -Value 7 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "AutoApproveOSDumps" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInChangeNotification" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\PushToInstall" -Name "DisablePushToInstall" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "BluetoothPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001" -Name "FeatureStates" -Type DWord -Value 892 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\ABCH" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\ABCH-SKYPE" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-2690168419-1548080425-1981415874-1001\SocialNetworks\FACEBOOK" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\DiagTrack" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\DoSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\lfsvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WbioSrvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\WSearch" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "NetworkPredictionOptions" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SearchSuggestEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillAddressEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "ResolveNavigationErrorsUseWebService" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AlternateErrorPagesEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SendSiteInfoToImproveServices" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "MetricsReportingEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PaymentMethodQueryEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AddressBarMicrosoftSearchInBingProviderEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "UserFeedbackAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "TrackingPrevention" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "DefaultGeolocationSetting" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "AllowServicePoweredQSA" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Onedrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Onedrive" -Name "DisableFileSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Onedrive" -Name "DisableMeteredNetworkFileSync" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote" -Name "Type" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Services\SysMain" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowBlockingAppsAtShutdown" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value N | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" -Name "SummaryNotificationDisabled" -TypeDWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Notifications\Data" -Name "418A073AA3BC3475" -Type Binary -Value ([byte[]](62, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 1, 2, 4, 0)) | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type String -Value "1000" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shell\cmd" -Name "HideBasedOnVelocityId" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\cmd" -Name "HideBasedOnVelocityId" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\PowerShell\cmd" -Name "ShowBasedOnVelocityId" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" | Out-Null
    Remove-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" | Out-Null
    If ($IsAdmin) {
        $u = New-Object System.Security.Principal.NTAccount($env:UserName)
        RegistryUserSettings $($u.Translate([System.Security.Principal.SecurityIdentifier]).value)
    }
}
function RegistryUserSettings($uid = "") {
    $regpath = "HKCU:"
    if ($uid.length -gt 0) {
        $regpath = "HKU:\$uid"
    }
    Write-Host -ForegroundColor Cyan "Adding privacy respecting user defaults..."
    mkdir "$regpath\Printers\Defaults"
    mkdir "$regpath\Software\Microsoft\Clipboard"
    mkdir "$regpath\Software\Microsoft\Input\TIPC"
    mkdir "$regpath\Software\Microsoft\Siuf\Rules"
    mkdir "$regpath\Software\Microsoft\Narrator\NoRoam"
    mkdir "$regpath\Software\Microsoft\WindowsMitigation"
    mkdir "$regpath\Software\Microsoft\InputPersonalization"
    mkdir "$regpath\Software\Microsoft\MediaPlayer\Preferences"
    mkdir "$regpath\Software\Policies\Microsoft\Office\15.0\osm"
    mkdir "$regpath\Software\Policies\Microsoft\Office\16.0\osm"
    mkdir "$regpath\Software\Microsoft\Personalization\Settings"
    mkdir "$regpath\Software\Policies\Microsoft\Windows\Explorer"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CDP"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SearchSettings"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell"
    mkdir "$regpath\Software\Policies\Microsoft\WindowsMediaPlayer"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Search"
    mkdir "$regpath\Software\Microsoft\Windows Security Health\State"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival"
    mkdir "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    mkdir "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    mkdir "$regpath\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    mkdir "$regpath\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout"
    mkdir "$regpath\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"
    mkdir "$regpath\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32"
    mkdir "$regpath\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"
    mkdir "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
    mkdir "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
    ForEach ($k in (Get-ChildItem "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
        if ($k.PSChildName -eq "LooselyCoupled") {
            continue
        }
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\$($k.PSChildName)" -Name "Type" -Type String -Value "InterfaceClass" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\$($k.PSChildName)" -Name "Value" -Type String -Value "Deny" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\$($k.PSChildName)" -Name "InitialAppValue" -Type String -Value "Unspecified" | Out-Null
    }
    Get-ChildItem -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach-Object {
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1 | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    }
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Narrator\NoRoam" -Name "WinEnterLaunchEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\WindowsMitigation" -Name "UserPreference" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival" -Name "(Default)" -Type String -Value "MSTakeNoAction" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" -Name "(Default)" -Type String -Value "MSTakeNoAction" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival" -Name "(Default)" -Type String -Value "MSTakeNoAction" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival" -Name "(Default)" -Type String -Value "MSTakeNoAction" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144, 18, 3, 128, 16, 0, 0, 0)) | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Printers\Defaults" -Name "NetID" -Type String -Value "{00000000-0000-0000-0000-000000000000}" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" -Name "DoNotTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" -Name "DisallowDefaultBrowserPrompt" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" -Name "FPEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type String -Value "" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type String -Value "" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContact" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Type String -Value "https://start.duckduckgo.com" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationOnLockScreenEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "SignInMode" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type String -Name "Value" -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Type" -Type String -Value "LooselyCoupled" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "InitialAppValue" -Type String -Value "Unspecified" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCortanaButton" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy" -Name "Favorites" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255)) | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "BackupPolicy" -Type DWord -Value 0x3c | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "DeviceMetadataUploaded" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "PriorLogons" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "StartUpTab" -Type DWord -Value 5 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableLogging" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableLogging" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Personalization\Settings" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "AutoSuggest" -Type String -Value "no" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "NetworkPredictionOptions" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "SearchSuggestEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "AutofillAddressEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "ResolveNavigationErrorsUseWebService" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "AlternateErrorPagesEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "SendSiteInfoToImproveServices" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "MetricsReportingEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "PaymentMethodQueryEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "AddressBarMicrosoftSearchInBingProviderEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "UserFeedbackAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "TrackingPrevention" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Policies\Microsoft\Edge" -Name "DefaultGeolocationSetting" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "Use FormSuggest" -Type String -Value "no" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "FormSuggest PW Ask" -Type String -Value "no" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\IntelliForms" -Name "AskUser" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\SearchScopes" -Name "ShowSearchSuggestionsInAddressGlobal" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\AutoComplete" -Name "Append Completion" -Type String -Value "no" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "HideNewEdgeButton" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\OneDrive" -Name "DisablePersonalSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "AutoEndTasks" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsCalculator_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\windows.immersivecontrolpanel_cw5n1h2txyewy" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MSPaint_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsStore_8wekyb3d8bbwe" -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "HungAppTimeout" -Type String -Value "1000" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value "0" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type String -Value "2000" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Type String -Value "1000" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "LinkResolveIgnoreLinkInfo" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveSearch" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoResolveTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Force -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Type DWord -Value 1 | Out-Null
    Remove-ItemProperty -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue | Out-Null
}

[Console]::ForegroundColor = "White"
[Console]::BackgroundColor = "Black"
Clear-Host

Write-Host -ForegroundColor Yellow @'
Windows10 Privacy Fixup
 - 2020 - 2022 iDigitalFlame

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

'@
Write-Host -ForegroundColor Red @'
This will break ALOT of things, YOU HAVE BEEN WARNED!!

'@

If (!$IsAdmin) {
    Write-Host -ForegroundColor White "Opening an admin version. Please accept the UAC prompt."
    Start-Process -Wait -Verb RunAs powershell.exe $InvokeMe
}
Else {
    Set-MpPreference -DisableRealtimeMonitoring $true
    If (!(Get-MpPreference).DisableRealtimeMonitoring) {
        Write-Host -ForegroundColor DarkRed "Please disable Windows Defender's Tamper Protection to continue!"
        Start-Process explorer.exe "windowsdefender:"
        While (!(Get-MpPreference).DisableRealtimeMonitoring) {
            Set-MpPreference -DisableRealtimeMonitoring $true
            Start-Sleep -Seconds 1
        }
    }
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIntrusionPreventionSystem $true
    Set-MpPreference -DisableScriptScanning $true
}

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null

TaskSettings
PowerSettings
FolderSettings
PackageSettings
NetworkSettings
FeatureSettings
ServiceSettings
OneDriveSettings
RegistrySettings $IsAdmin
RegistryUserSettings

If ($IsAdmin) {
    New-Item -ItemType Directory -Path "$env:TEMP\vive" -ErrorAction SilentlyContinue | Out-Null
    Invoke-WebRequest -Uri "https://github.com/thebookisclosed/ViVe/releases/download/v0.2.1/ViVeTool-v0.2.1.zip" -OutFile "$env:TEMP\vive\vive.zip" -ErrorAction SilentlyContinue | Out-Null
    Expand-Archive -LiteralPath "$env:TEMP\vive\vive.zip" -DestinationPath "$env:TEMP\vive\"  -ErrorAction SilentlyContinue | Out-Null
    Start-Process -Wait -FilePath "$env:TEMP\vive\ViVeTool.exe" -ArgumentList @("addconfig", "31950543", "1") -ErrorAction SilentlyContinue | Out-Null
    Start-Process -Wait -FilePath "$env:TEMP\vive\ViVeTool.exe" -ArgumentList @("addconfig", "18299130", "1") -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$env:TEMP\vive" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
}

Remove-PSDrive HKU -ErrorAction SilentlyContinue | Out-Null
Remove-PSDrive HKCR -ErrorAction SilentlyContinue | Out-Null

If (!$IsAdmin) {
    Write-Host -ForegroundColor Green "Done! Please restart to update all settings!"
}

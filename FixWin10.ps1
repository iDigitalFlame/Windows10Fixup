# iDigitalFlame
#  Fix everything wrong with Windows 10.
#  Warning, this will break ALOT of things in Windows (like Edge), so be warned.
#
# Copyright (C) 2020 iDigitalFlame
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

$ErrorActionPreference = "SilentlyContinue"

function mkdir($dir) {
    if (Test-Path $dir) {
        return
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
function TaskSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up Tasks..."
    Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false | Out-Null
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
}
Function StartSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up Start..."
    Remove-Item -Force "$($env:USERPROFILE)\Desktop\Microsoft edge.lnk" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\3D Objects" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Contacts" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Favorites" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Pictures" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\MicrosoftEdgeBackups" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Music" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Saved Games" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Searches" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -Recurse "$($env:USERPROFILE)\Videos" -ErrorAction SilentlyContinue | Out-Null
    If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
            $d = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
            $d = $data.Substring(0, $d.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
            Set-ItemProperty -ErrorAction SilentlyContinue -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $d.Split(",") -ErrorAction SilentlyContinue | Out-Null
        }
    }
    ElseIf ([System.Environment]::OSVersion.Version.Build -eq 17133) {
        $k = Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Recurse | Where-Object { $_ -like "*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current" }
        $d = (Get-ItemProperty -Path $k.PSPath -Name "Data").Data[0..25] + ([byte[]](202, 50, 0, 226, 44, 1, 1, 0, 0))
        Set-ItemProperty -ErrorAction SilentlyContinue -Path $k.PSPath -Name "Data" -Type Binary -Value $d -ErrorAction SilentlyContinue | Out-Null
    }
}
function PowerSettings() {
    Write-Host -ForegroundColor Green "Fixing Power Settings..."
    Disable-MMAgent -mc -ErrorAction SilentlyContinue | Out-Null
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
Function PackageSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up AppxPackages..."
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

    $p = @(
        "Anytime"
        "BioEnrollment"
        "Browser"
        "ContactSupport"
        "Defender"
        "Feedback"
        "Flash"
        "Gaming"
        "Holo"
        "InternetExplorer"
        "Maps"
        "MiracastView"
        "OneDrive"
        "SecHealthUI"
        "Wallet"
    )
    foreach ($i in $p) {
        $m = (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" | Where-Object Name -Like "*$i*")
        foreach ($n in $m) {
            Set-ItemProperty -ErrorAction SilentlyContinue -Path ("HKLM:" + $n.Name.Substring(18)) -Name Visibility -Value 1 -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path ("HKLM:" + $n.Name.Substring(18)) -Name DefVis -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path ("HKLM:" + $n.Name.Substring(18) + "\Owners") -ErrorAction SilentlyContinue | Out-Null
            dism.exe /Online /Remove-Package /PackageName:$($n.Name.split('\')[-1]) /NoRestart | Out-Null
        }
    }
}
function NetworkSettings() {
    Write-Host -ForegroundColor Green "Fixing Network Settings..."
    Enable-NetFirewallRule -Name "RemoteDesktop*" -ErrorAction SilentlyContinue | Out-Null
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue | Out-Null
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
}
function FeatureSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up Features..."
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "SearchEngine-Client-Package" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Quick Assist.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows Fax and Scan.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Wordpad.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\Programdata\Microsoft\Windows\Start Menu\Programs\MiracastView.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
}
function ServiceSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up Services..."
    Set-Service "AppReadiness" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
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
    Set-Service "diagsvr" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
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
    Set-Service "TapiSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "Themes" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TokenBroker" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TroubleshootingSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "UevAgentService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "upnphost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "VacSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "VSS" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WarpJITSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WalletService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wcnsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wcncsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WdiServiceHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WdiSystemHost" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WebClient" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WEPHOSTSVC" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wercplsupport" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WersVR" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WFDSConMgrSvr" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null # NE
    Set-Service "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "workfoldersvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null #ne
    Set-Service "WpcMonSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WpnService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "WpnUserService" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblGamesave" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "XblGipSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null # ne
    Set-Service "XboxNetApiSvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "AJRouter" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "ndu" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "TrkWks" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Set-Service "wscvc" -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
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
Function OneDriveSettings() {
    Write-Host -ForegroundColor Green "Cleaning Up OneDrive..."
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -s 2
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

    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -ErrorAction SilentlyContinue | Out-Null

    foreach ($i in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
        Remove-Item -Recurse -Force $i.FullName -ErrorAction SilentlyContinue | Out-Null
    }

    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null

    mkdir "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    mkdir "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"

    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 -ErrorAction SilentlyContinue | Out-Null

    Remove-ItemProperty "HKU:\Default\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force -ErrorAction SilentlyContinue | Out-Null
}
function RegistrySettings() {
    Write-Host -ForegroundColor Green "Cleaning Up Registry (System)..."
    mkdir "HKLM:\Software\Microsoft\WlanSvc\AnqpCache"
    mkdir "HKLM:\Software\Policies\Microsoft\WindowsStore"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\GameDVR"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"
    mkdir "HKLM:\Software\Policies\Microsoft\Internet Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Addons"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
    mkdir "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization"
    mkdir "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender"
    mkdir "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    mkdir "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    mkdir "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    mkdir "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    mkdir "HKLM:\Software\Wow6432Node\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder"
    mkdir "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
    mkdir "HKLM:\Software\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    mkdir "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote"
    mkdir "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\FACEBOOK"
    mkdir "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH-SKYPE"
    mkdir "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"

    ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
        New-Item -ErrorAction SilentlyContinue -Path $("HKCR:\$type\shell\open") -Force | Out-Null
        New-Item -ErrorAction SilentlyContinue -Path $("HKCR:\$type\shell\open\command") | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" | Out-Null
    }

    Set-Item "HKLM:\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""

    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Name "Attributes" -Type DWord 0 -Value 0xA0100000 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCR:\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" -Name "Attributes" -Value 0xB0040064 | Out-Null

    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" "WiFiSenseCredShared" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" "WiFiSenseOpen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "DiagTrackAuthorization" -Type DWord -Value 7 | Out-Null
    New-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SpecialRoamingOverrideAllowed" -PropertyType DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\WlanSvc\AnqpCache" -Name "OsuRegistrationStatus" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xB0040064 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -Name "Attributes" -Type DWord -Value 0xA0100000 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableFileSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableMeteredNetworkFileSync" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\FACEBOOK" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH-SKYPE" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118\SocialNetworks\ABCH" -Name "OptInStatus" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\S-1-5-21-966265688-3624610909-2545133441-1118" -Name "FeatureStates" -Type DWord -Value 381 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Launcher_QuickNote" -Name "Type" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\Sense" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\Sense" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\DoSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\wscsvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\mpssvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\PcaSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\WdNisSvc" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\WdNisSvc" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "Start" -Type DWord -Value 4 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Services\WinDefend" -Name "AutorunsDisabled" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value 0 | Out-Null

    Remove-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue | Out-Null

    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue | Out-Null

    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        $u = New-Object System.Security.Principal.NTAccount($env:UserName)
        $i = $u.Translate([System.Security.Principal.SecurityIdentifier]).value
        RegistryUserSettings $i
    }
}
function RegistryUserSettings($uid = "") {
    $regpath = "HKCU:"
    if ($uid.length -gt 0) {
        $regpath = "HKU:\$uid"
    }
    Write-Host -ForegroundColor Green "Cleaning Up Registry (User)..."
    mkdir "$regpath\Printers\Defaults"
    mkdir "$regpath\Software\Microsoft\Input\TIPC"
    mkdir "$regpath\Software\Microsoft\Siuf\Rules"
    mkdir "$regpath\Software\Microsoft\InputPersonalization"
    mkdir "$regpath\Software\Microsoft\Personalization\Settings"
    mkdir "$regpath\Software\Policies\Microsoft\Windows\Explorer"
    mkdir "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    mkdir "$regpath\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout"
    mkdir "$regpath\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    mkdir "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
    mkdir "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
    mkdir "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
    mkdir "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"

    ForEach ($k in (Get-ChildItem "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
        if ($k.PSChildName -eq "LooselyCoupled") {
            continue
        }
        Set-ItemProperty -ErrorAction SilentlyContinue -Path ("$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $k.PSChildName) -Name "Type" -Type String -Value "InterfaceClass" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Path ("$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $k.PSChildName) -Name "Value" -Type String -Value "Deny" | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Path ("$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $k.PSChildName) -Name "InitialAppValue" -Type String -Value "Unspecified" | Out-Null
    }
    Get-ChildItem -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach-Object {
        Set-ItemProperty -ErrorAction SilentlyContinue -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1 | Out-Null
        Set-ItemProperty -ErrorAction SilentlyContinue -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1 | Out-Null
    }

    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144, 18, 3, 128, 16, 0, 0, 0)) | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Printers\Defaults" -Name "NetID" -Type String -Value "{00000000-0000-0000-0000-000000000000}" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" -Name "DoNotTrack" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" -Name "DisallowDefaultBrowserPrompt" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" -Name "FPEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContact" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Type String -Value "https://start.duckduckgo.com" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationOnLockScreenEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Type" -Type String -Value "LooselyCoupled" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "Value" -Type String -Value "Deny" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" -Name "InitialAppValue" -Type String -Value "Unspecified" | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCortanaButton" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy" -Name "Favorites" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255)) | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "BackupPolicy" -Type DWord -Value 0x3c | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "DeviceMetadataUploaded" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync" -Name "PriorLogons" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" -Name "Enabled" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "StartUpTab" -Type DWord -Value 5 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\Software\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 0 | Out-Null
    Set-ItemProperty -ErrorAction SilentlyContinue -Path "$regpath\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 | Out-Null

    Remove-ItemProperty -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue | Out-Null

    Remove-Item -Path "$regpath\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue | Out-Null
}

# Run This Script as Administrator First, then run as user.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    If ($Invocation.MyCommand.Path.length -eq 0) {
        Start-Process -Wait -Verb RunAs powershell.exe "-NoProfile -ExecutionPolicy Unrestricted -Command `"Invoke-WebRequest -UseBasicParsing 'https://dij.sh/win10' | Invoke-Expression`""
    }
    Else {
        Start-Process -Wait -Verb RunAs powershell.exe "-NoProfile -ExecutionPolicy Unrestricted -File `"$PSCommandPath`""
    }
}

Write-Host -ForegroundColor Cyan "Windows10 (Un)Fucker."

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null

TaskSettings
StartSettings
PowerSettings
PackageSettings
NetworkSettings
FeatureSettings
ServiceSettings
OneDriveSettings
RegistrySettings
RegistryUserSettings

Remove-PSDrive HKU -ErrorAction SilentlyContinue | Out-Null
Remove-PSDrive HKCR -ErrorAction SilentlyContinue | Out-Null

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host -ForegroundColor Green "Done. Please restart and run one more time!"
}

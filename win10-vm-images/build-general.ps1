<#  
.SYNOPSIS  
    Custimization script for Azure Image Builder including Microsoft recommneded configuration to be included in a Windows 10 ms Master Image including Office
.
.DESCRIPTION  
    Customization script to build a WVD Windows 10ms image
    This script configures the Microsoft recommended configuration for a Win10ms image:
        Article:    Prepare and customize a master VHD image 
                    https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image 
        Article: Install Office on a master VHD image 
                    https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
.
NOTES  
    File Name  : Win10ms_O365.ps1
    Author     : Roel Schellens with Modifications by Isaac Stith & Daniel Hibbert
    Version    : v0.0.2
.
.EXAMPLE
    This script can be used in confuction with an packer build prvisioner to configure the WVD Multi-session host
.
.DISCLAIMER
    1 - All configuration settings in this script need to be validated and tested in your own environment.
    2 - Ensure to confirm the documentation online has not been updated and therefor might include different settings
    3 - Where possible also the use of Group Policies can be used.
    4 - The below script uses the Write-Host command to allow you to better troubleshoot the activity from within the Packer logs.
    5 - To get more verbose logging of the script remove the | Out-Null at the end of the PowerShell command
#>

Write-Host '*** WVD AIB CUSTOMIZER PHASE **************************************************************************************************'
Write-Host '*** WVD AIB CUSTOMIZER PHASE ***                                                                                            ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Script: build-general.ps1                                                                   ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE ***                                                                                            ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE **************************************************************************************************'

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Stop the custimization when Error occurs ***'
$ErroractionPreference='Stop'

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Set Custimization Script Variables ***'
#NOTE: Make sure to update these variables for your environment!!! ***
# Note: Only needed when Onedrive needs to be configured (see below). When using the Marketplace Image including Office this is not required.
#$AADTenantID = "<your-AzureAdTenantId>"

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** Create temp folder for software packages. ***'
New-Item -Path 'C:\temp' -ItemType Directory -Force | Out-Null

#FS Logix Now included by default in Multi-sesison images
#Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install FSLogix ***'
# Note: Settings for FSLogix can be configured through GPO's)
#Invoke-WebRequest -Uri 'https://aka.ms/fslogix_download' -OutFile 'c:\temp\fslogix.zip'
#Expand-Archive -Path 'C:\temp\fslogix.zip' -DestinationPath 'C:\temp\fslogix\'  -Force
#Invoke-Expression -Command 'C:\temp\fslogix\x64\Release\FSLogixAppsSetup.exe /install /quiet /norestart'
#Start-Sleep -Seconds 10

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** START OS CONFIG *** Update the recommended OS configuration ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Disable Automatic Updates ***'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value '1' -PropertyType DWORD -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Specify Start layout for Windows 10 PCs (optional) ***'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SpecialRoamingOverrideAllowed' -Value '1' -PropertyType DWORD -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Set up time zone redirection ***'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableTimeZoneRedirection' -Value '1' -PropertyType DWORD -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Disable Storage Sense ***'
# reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense' -Name 'AllowStorageSenseGlobal' -Value '0' -PropertyType DWORD -Force | Out-Null

# Note: Remove if not required!
#Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** For feedback hub collection of telemetry data on Windows 10 Enterprise multi-session ***'
#New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value '3' -PropertyType DWORD -Force | Out-Null

# Note: Remove if not required!
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEYS *** Fix 5k resolution support ***'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MaxMonitors' -Value '4' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MaxXResolution' -Value '5120' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MaxYResolution' -Value '2880' -PropertyType DWORD -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs' -Name 'MaxMonitors' -Value '4' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs' -Name 'MaxXResolution' -Value '5120' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs' -Name 'MaxYResolution' -Value '2880' -PropertyType DWORD -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Temp fix for 20H1 SXS Bug ***'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs' -Name 'fReverseConnectMode' -Value '1' -PropertyType DWORD -Force | Out-Null

# Note: It is recommended to set user settings through GPO's.
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** START OFFICE CONFIG *** Config the recommended Office configuration ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG OFFICE Regkeys *** Mount default registry hive ***'
& REG LOAD HKLM\DEFAULT C:\Users\Default\NTUSER.DAT
Start-Sleep -Seconds 5
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG OFFICE *** Set InsiderslabBehavior ***'
New-Item -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\office\16.0\common' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\office\16.0\common' -Name 'InsiderSlabBehavior' -Value '2' -PropertyType DWORD -Force | Out-Null
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG OFFICE *** Set Outlooks Cached Exchange Mode behavior ***'
New-ItemProperty -Path 'HKLM:\DEFAULT\software\policies\microsoft\office\16.0\outlook\cached mode' -Name 'enable' -Value '1' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\DEFAULT\software\policies\microsoft\office\16.0\outlook\cached mode' -Name 'syncwindowsetting' -Value '1' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\DEFAULT\software\policies\microsoft\office\16.0\outlook\cached mode' -Name 'CalendarSyncWindowSetting' -Value '1' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\DEFAULT\software\policies\microsoft\office\16.0\outlook\cached mode' -Name 'CalendarSyncWindowSettingMonths' -Value '1' -PropertyType DWORD -Force | Out-Null
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG OFFICE Regkeys *** Un-mount default registry hive ***'
[GC]::Collect()
& REG UNLOAD HKLM\DEFAULT
Start-Sleep -Seconds 5

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG OFFICE Regkeys *** Set Office Update Notifiations behavior ***'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate' -Name 'hideupdatenotifications' -Value '1' -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate' -Name 'hideenabledisableupdates' -Value '1' -PropertyType DWORD -Force | Out-Null



Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Azure Information Protection mode ***'

Invoke-WebRequest -Uri 'https://download.microsoft.com/download/4/9/1/491251F7-46BA-46EC-B2B5-099155DD3C27/AzInfoProtection_UL_MSI_for_central_deployment.msi' -OutFile 'c:\temp\AIP.msi'
Invoke-Expression -Command 'msiexec /i C:\temp\AIP.msi /quiet /l*v C:\temp\aipinstall.log'
Start-Sleep -Seconds 60
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG AIP  *** Configure AIP for GCC. ***'
#create registry itme where the cloud env type is for Azure information protection: see https://docs.microsoft.com/en-us/enterprise-mobility-security/solutions/ems-aip-premium-govt-service-description
New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP -Name CloudEnvType -PropertyType DWORD -Value 1 -Force
Start-Sleep -Seconds 30




Write-Host '*** WVD AIB CUSTOMIZER PHASE ********************* END *************************'


# Install Choco
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install visual studio code (choco)
choco install vscode --confirm
# Install visual studio 2019 CE (choco)
#choco install visualstudio2019community --confirm
# Install Google Chrome
choco install googlechrome --confirm
# Install git
choco install git.install --confirm
# Install putty
choco install putty.install --confirm
# Install Azure Powershell Module (AZ)
choco install az.powershell --confirm
# Install Azure CLI
choco install azure-cli --confirm
# Install Azure Storage Explorer
choco install microsoftazurestorageexplorer --confirm
# Install AzCopy
choco install azcopy --confirm
# Install WVD Agent
choco install wvd-agent --confirm


 
 # Sysprep - Generalize virtual machine (Required)
 while ((Get-Service RdAgent).Status -ne 'Running') { Start-Sleep -s 5 }
 while ((Get-Service WindowsAzureGuestAgent).Status -ne 'Running') { Start-Sleep -s 5 }
 & $env:SystemRoot\\System32\\Sysprep\\Sysprep.exe /oobe /generalize /quiet /quit
 while($true) { $imageState = Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State | `
         Select-Object ImageState; `
                if($imageState.ImageState -ne 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') { Write-Output $imageState.ImageState; Start-Sleep -s 10  } `
                else { break } }
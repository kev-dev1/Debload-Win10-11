@echo off

fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)

echo "Set Privacy Configuration"

if exist "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" (
    takeown /f "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r /d y
    icacls "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    echo "" > "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    echo Clear successful: "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
) else (
    echo "Main telemetry file not exist!"
)

sc stop "MapsBroker" & sc config "MapsBroker" start=disabled

sc stop "RetailDemo" & sc config "RetailDemo" start=disabled

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('OneSyncSvc', 'OneSyncSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f

reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f

reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f

reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
sc stop "diagnosticshub.standardcollector.service" & sc config "diagnosticshub.standardcollector.service" start=disabled
sc stop "diagsvc" & sc config "diagsvc" start=disabled

schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE

reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f

reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f

reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f

reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f

reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f

sc stop "DoSvc" & sc config "DoSvc" start=disabled

sc stop "PcaSvc" & sc config "PcaSvc" start=disabled

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('PimIndexMaintenanceSvc', 'PimIndexMaintenanceSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('UserDataSvc', 'UserDataSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('MessagingService', 'MessagingService_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('UnistoreSvc', 'UnistoreSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /d 0 /t "REG_DWORD" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
if not %PROCESSOR_ARCHITECTURE%==x86 ( REM is 64 bit?
    reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
)

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /d 0 /t REG_DWORD /f

reg add "HKLM\SOFTWARE\Microsoft\OEM\Device\Capture" /v "NoPhysicalCameraLED" /d 1 /t REG_DWORD /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

curl "https://raw.githubusercontent.com/kev-dev1/Debload-Win10-11/master/ooshutup10.cfg" -o ooshutup10.cfg
curl "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -o OOSU10.exe
OOSU10.exe ooshutup10.cfg /quiet

w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"

SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(
    net stop w32time
)

net start w32time
w32tm /config /update
w32tm /resync

echo "Configuration finish"

echo "Set Minimalistic Configuration"

taskkill /f /im OneDrive.exe

if %PROCESSOR_ARCHITECTURE%==x86 (
    %SystemRoot%\System32\OneDriveSetup.exe /uninstall 2>nul
) else (
    %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall 2>nul
)

rd "%UserProfile%\OneDrive" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
rd "%SystemDrive%\OneDriveTemp" /q /s

del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSyncNGSC" /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSync" /d 1 /f

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f

reg load "HKU\Default" "%SystemDrive%\Users\Default\NTUSER.DAT"
reg delete "HKU\Default\software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "HKU\Default"

reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
reg add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f

for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F

reg delete "HKCU\Environment" /v "OneDrive" /f

sc stop "MapsBroker" & sc config "MapsBroker" start=disabled

sc stop "RetailDemo" & sc config "RetailDemo" start=disabled

PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('OneSyncSvc', 'OneSyncSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

sc stop "XblAuthManager" & sc config "XblAuthManager" start=disabled

sc stop "XblGameSave" & sc config "XblGameSave" start=disabled

sc stop "XboxNetApiSvc" & sc config "XboxNetApiSvc" start=disabled

PowerShell -ExecutionPolicy Unrestricted -Command "$installer = (Get-ChildItem "^""$env:ProgramFiles*\Microsoft\Edge\Application\*\Installer\setup.exe"^""); if (!$installer) {; Write-Host 'Could not find the installer'; } else {; & $installer.FullName -Uninstall -System-Level -Verbose-Logging -Force-Uninstall; }"

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Appconnector' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.549981C3F5F10' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GetHelp' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Getstarted' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MixedReality.Portal' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsFeedbackHub' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsCamera' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MSPaint' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MinecraftUWP' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Print3D' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.OneConnect' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftStickyNotes' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.SkypeApp' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GroupMe10' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsSoundRecorder' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Microsoft3DViewer' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingWeather' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingSports' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingNews' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingFinance' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftOfficeHub' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.Sway' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxApp' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Xbox.TCUI' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGameOverlay' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxIdentityProvider' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsStore' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Wallet' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.StorePurchaseApp' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.Phone' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.CommsPhone' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Advertising.Xaml' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.RemoteDesktop' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.NetworkSpeedTest' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Todos' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ShazamEntertainmentLtd.Shazam' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSaga' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSodaSaga' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Flipboard.Flipboard' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage '9E2F88E3.Twitter' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ClearChannelRadioDigital.iHeartRadio' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'PandoraMediaInc.29680B314EFC2' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage '46928bounde.EclipseManager' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ActiproSoftwareLLC.562882FEEB491' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'SpotifyAB.SpotifyMusic' | Remove-AppxPackage"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'InputApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.AAD.BrokerPlugin'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.AccountsControl'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.AsyncTextService'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.ContactSupport'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.Print3D'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.ECApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.MicrosoftEdge'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.MicrosoftEdgeDevToolsClient'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.PPIProjection'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.Apprep.ChxApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.AssignedAccessLockApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.CapturePicker'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.CloudExperienceHost'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.ContentDeliveryManager'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.Holographic.FirstRun'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.OOBENetworkCaptivePortal'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.OOBENetworkConnectionFlow'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.ParentalControls'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.PeopleExperienceHost'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.WindowsFeedback'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.XboxGameCallableUI'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.CBSPreview'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName =  $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }"

dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /NoRestart

dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-Clients" /NoRestart

dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Tools-All" /NoRestart

dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-PowerShell" /NoRestart

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'MathRecognizer*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'OneCoreUAP.OneSync*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'App.Support.QuickAssist*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'App.StepsRecorder*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'Analog.Holographic.Desktop*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'Microsoft.Windows.StorageManagement*' | Remove-WindowsCapability -Online"

PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'Microsoft.OneCore.StorageManagement*' | Remove-WindowsCapability -Online"

dism /online /Set-ReservedStorageState /State:Disabled /NoRestart

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f

echo "Configuration finish"

echo "Install WinGet"

if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
    echo 'Winget Already Installed'
}
else{
	echo "Winget not found, installing it now."
    $ResultText.text = "`r`n" +"`r`n" + "Installing Winget... Please Wait"
	PowerShell Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
	$nid = (Get-Process AppInstaller).Id
	PowerShell Wait-Process -Id $nid
	echo "Winget Installed"

echo "WinGet Install finish"

echo "Install Programms"

echo "Install Firefox"
winget install Mozilla.Firefox
echo "Installation finish"

echo "Install Thunderbird"
winget install Mozilla.Thunderbird
echo "Installation finish"

echo "Install Libreoffice"
winget install LibreOffice.LibreOffice
echo "Installation finish"

echo "Install Lector PDF"
winget install SagarGurtu.Lector
echo "Installation finish"

echo "Install Microsoft Powertoys"
winget install Microsoft.Powertoys
echo "Installation finish"

echo "Finish Install Programms"
pause
exit /b 0

@echo off

fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)

echo Clear telemetry file
if exist "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" (
    takeown /f "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r /d y
    icacls "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    echo "" > "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    echo Clear successful: "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
) else (
    echo "Main telemetry file not exist!"
)

echo Downloaded Maps Manager
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled

echo Microsoft Retail Demo experience
sc stop "RetailDemo" & sc config "RetailDemo" start=disabled

echo Sync Host (OneSyncSvc) Service Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('OneSyncSvc', 'OneSyncSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

echo Disable cloud speech recognition
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f

echo Disable active probing (pings to MSFT NCSI server)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f

echo Opt out from Windows privacy consent
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f

echo Disable Windows feedback
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

echo Disable text and handwriting collection
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

echo Turn off sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f

echo Disable Wi-Fi sense
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

echo Hide most used apps (tracks app launch)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f

echo Disable Auto Downloading Maps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f

echo Disable steps recorder
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

echo Disable game screen recording
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

echo Disable feedback on write (sending typing info)
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f

echo Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f

echo Disable Customer Experience Improvement (CEIP/SQM)
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

echo Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f

echo Disable diagnostics telemetry
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
sc stop "diagnosticshub.standardcollector.service" & sc config "diagnosticshub.standardcollector.service" start=disabled
sc stop "diagsvc" & sc config "diagsvc" start=disabled

echo Disable Customer Experience Improvement Program
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE

echo Disable telemetry in data collection policy
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

echo Disable apps and Cortana to activate with voice
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f

echo Disable apps and Cortana to activate with voice when sytem is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f

echo Turn off Windows Location Provider
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f

echo Turn off location scripting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f

echo Turn off location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f

echo Do not allow search to use location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

echo Disable web search in search bar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f

echo Do not search the web or display web results in Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f

echo Disable Bing search
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

echo Do not allow Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

echo Do not allow Cortana experience
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f

echo Do not allow search and Cortana to search cloud sources like OneDrive and SharePoint
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f

echo Disable Cortana speech interaction while the system is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f

echo Opt out from Cortana consent
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

echo Do not allow Cortana to be enabled
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f

echo Disable Cortana (Internet search results in start menu)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f

echo Remove the Cortana taskbar icon
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowCortanaButton" /t REG_DWORD /d 0 /f

echo Disable Cortana in ambient mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f

echo Prevent Cortana from displaying history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f

echo Prevent Cortana from using device history
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f

echo Disable "Hey Cortana" voice activation
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f

echo Disable Cortana listening to commands on Windows key + C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f

echo Disable using Cortana even when device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f

echo Disable ad customization with Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f

echo Turn Off Suggested Content in Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f

echo Disable Windows Tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f

echo Disable Windows Spotlight (random wallpaper on lock screen)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f

echo Disable Microsoft consumer experiences
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f

echo Remove "Windows Insider Program" from Settings
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f

echo Disable all settings sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f

echo Disable Application Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable App Sync Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable Desktop Theme Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable Personalization Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable Start Layout Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable Web Browser Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Disable Windows Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f

echo Delivery Optimization (P2P Windows Updates)
sc stop "DoSvc" & sc config "DoSvc" start=disabled

echo Program Compatibility Assistant Service
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled

echo Contact data indexing
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('PimIndexMaintenanceSvc', 'PimIndexMaintenanceSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

echo App user data access
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('UserDataSvc', 'UserDataSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

echo --- Text messaging
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('MessagingService', 'MessagingService_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

echo User Data Storage (UnistoreSvc) Service
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQueries = @('UnistoreSvc', 'UnistoreSvc_*'); foreach ($serviceQuery in $serviceQueries) {; $service = Get-Service -Name $serviceQuery -ErrorAction Ignore; if(!$service) {; Write-Host "^""Service `"^""$serviceQuery`"^"" is not found, no action is needed"^""; continue; }; $name = $service.Name; Stop-Service $name -ErrorAction SilentlyContinue; if($?) {; Write-Host "^""Stopped `"^""$name`"^"""^""; } else {; Write-Warning "^""Could not stop `"^""$name`"^"""^""; }; $regKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$name"^""; if(Test-Path $regKey) {; Set-ItemProperty $regKey -Name Start -Value 4 -Force; Write-Host "^""Disabled `"^""$name`"^"""^""; } else {; Write-Host "^""Service is not registered at Windows startup, no action is needed."^""; }; }"

echo --- Disable Live Tiles push notifications
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f

echo --- Turn off "Look For An App In The Store" option
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f

echo --- Do not show recently used files in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /d 0 /t "REG_DWORD" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
if not %PROCESSOR_ARCHITECTURE%==x86 ( REM is 64 bit?
    reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
)

echo --- Disable Sync Provider Notifications
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /d 0 /t REG_DWORD /f

echo --- Enable camera on/off OSD notifications
reg add "HKLM\SOFTWARE\Microsoft\OEM\Device\Capture" /v "NoPhysicalCameraLED" /d 1 /t REG_DWORD /f

echo --- Disable online tips
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f

echo --- Turn off Internet File Association service
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f

echo --- Turn off the "Order Prints" picture task
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f

echo --- Disable the file and folder Publish to Web option
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f

echo --- Prevent downloading a list of providers for wizards
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f

echo --- Do not keep history of recently opened documents
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f

echo --- Clear history of recently opened documents on exit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f

echo --- 3D Objects
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f


echo Running O&O Shutup with Recommended Settings
curl "https://raw.githubusercontent.com/kev-dev1/Debload-Win10-11/master/ooshutup10.cfg" -o ooshutup10.cfg
curl "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -o OOSU10.exe
OOSU10.exe ooshutup10.cfg /quiet

echo Change NTP (time) server to pool.ntp.org
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"

SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(
    net stop w32time
)

net start w32time
w32tm /config /update
w32tm /resync

pause
exit /b 0

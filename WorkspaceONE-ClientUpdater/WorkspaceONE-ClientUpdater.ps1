[CmdletBinding(SupportsShouldProcess)]
param([bool]$IsTesting,
    [String]$Agency,
    [string]$Version,
    [String]$Import
)

#region Invoke-SQLCommand
Function Invoke-SQLCommand {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Invoke-SQLCommand -Parameter $Value
.NOTES

#>
    Param ([string] $dataSource = ".\SQLEXPRESS",
        [string] $database = "MasterData",
        [string] $sqlCommand = $(throw "Please specify a query."),
        [string] $Username,
        [string] $Password
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
    }
    Process {

        if ($username) {
            $connectionString = "Server=$dataSource; Database=$database; User ID=$Username; Password=$Password;"
        } else {
            $connectionString = "Server=$dataSource; Database=$database;"
        }

        $connection = New-Object system.data.SqlClient.SQLConnection($connectionString)
        $command = New-Object system.data.sqlclient.sqlcommand($sqlCommand, $connection)
        $connection.Open()
        $adapter = New-Object System.Data.sqlclient.sqlDataAdapter $command
        $dataset = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $connection.Close()
        Write-Host "Number of results: $($dataSet.Tables.Rows.Count)"
        Write-Output -InputObject $dataSet.Tables
    }
    End {
    }
}
#endregion Invoke-SQLCommand

#region Get-Status
Function Get-Status {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-Status -Parameter $Value
.NOTES

#>
    Param ($Device
    )

    Begin {
    }
    Process {
        try {
            $OutputObject = Invoke-Command -ScriptBlock {
                $Apps = @()
                $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
                $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" # 64 Bit
                $temp = ($Apps | Where-Object { $_.DisplayName -like "*Workspace ONE Intelligent Hub Installer*" })
                $ReturnVersion = $temp.DisplayVersion
                $ReturnGUID = $temp.PSChildName
                $BootTime = Get-WmiObject -Class Win32_OperatingSystem | Select-Object @{LABEL = 'LastBootUpTime'; EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } }
                try {
                    $ServiceStatus = Get-Service -Name "AirWatchService" -ErrorAction SilentlyContinue
                } catch {
                    $ServiceStatus = "Not Running"
                }
                $LoggedOnUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username
                $Processes = Get-Process -IncludeUserName | Where-Object { ($_.Name -like "TaskScheduler") -OR ($_.Name -like "AwWindowsipc") -OR ($_.Name -like "AW.WinPC.Updater") }
                $output = [PSCustomObject]@{
                    LoggedOnUser  = $LoggedOnUser.Username
                    Version       = $ReturnVersion
                    BootTime      = $BootTime.LastBootUpTime
                    ServiceStatus = $ServiceStatus.Status
                    Processes     = $Processes
                    GUID          = $ReturnGUID
                }
                Write-Output -Input $output
            } -ComputerName $device -ErrorAction Stop
        } catch {
            Write-Host "Error"
            $OutputObject = [PSCustomObject]@{
                LoggedOnUser  = $_.Exception.Message
                Version       = ""
                BootTime      = ""
                ServiceStatus = ""
                Processes     = ""
                GUID          = ""
                Devicename    = $Device
            }
        }
        Write-Output -InputObject $OutputObject
    }
    End {
        #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-Status


[string]$scriptDirectory = $PSScriptRoot
if (!$Version) {
    # Get the version number from the txt file
    $UpdateFile = Get-ChildItem -Path (Get-Item -Path "$scriptDirectory").Parent.FullName -Filter *.txt -File
    $Version = ($UpdateFile.Name).Replace("Current Version ", "").Replace(".txt", "")
    Write-Host "Version detected as $Version"
} elseif ($Version -eq "latest") {
    $UpdateFolders = Get-ChildItem -Path (Get-Item -Path "$scriptDirectory").Parent.FullName -Directory | Where-Object { $_.Name -notlike "Script" } | Select-Object -Last 1
    $Version = $UpdateFolders.Name
    Write-Host "Version detected as $Version"
} else {
    Write-Host "Version set as $Version"
}

$SQLCommand = "SELECT APP.Version AS [Application Version], DAT.FriendlyName, DEV.LastSeen
FROM dbo.DeviceAttributes DAT
LEFT JOIN dbo.DeviceView DEV ON DAT.DeviceID = DEV.DeviceID
JOIN interrogator.ApplicationList AL ON DEV.DeviceID = AL.DeviceID
JOIN interrogator.Application APP ON AL.ApplicationID = APP.ApplicationID
WHERE APP.Name LIKE 'Workspace ONE Intelligent Hub Installer'
AND DEV.LastSeen >= DATEADD(day,-1, GETDATE())
AND APP.Version NOT LIKE '$Version.%'

ORDER BY DEV.LastSeen DESC"

if ($env:USERDNSDOMAIN -eq "") {
    $DataSource = ""
    $WS1Database = ""
    $ReadOnlyUsername = ""
    $ReadOnlyPassword = ""
    $ExcludedDevices = @("")
}  else {
    Write-Host "No Agency has been set, exiting"
    exit
}

$Location = "D:\iBuild Tools\Tools\pstools"
$OldPath = "D:\iBuild Tools\WS1Updater\21.5\AirWatchAgent.msi"
$NewPath = "D:\iBuild Tools\WS1Updater\$Version\AirWatchAgent.msi"

if ($Import) {
    $Devices = Import-Csv -Path $Import
    Write-Host "$(($Devices.FriendlyName).Count) devices imported from $Import"
} else {
    Write-Host "YOU ARE ABOUT TO CONNECT TO THE DATABASE AND UPGRADE EVERY DEVICE!" -ForegroundColor Red
    Write-Host "ARE YOU MEANT TO BE DOING THIS?!?!?!" -ForegroundColor Red
    $Response = Read-Host -Prompt "Confirm [y/n]?"

    if ($response -eq "y") {
        Write-Host "No seriously, are you meant to be doing this?" -ForegroundColor Red
        Write-Host "Do you have an open change to do this?" -ForegroundColor Red
        $Response = Read-Host -Prompt "Confirm [y/n]?"
        if ($Response -eq "y") {
            Write-Host "Alright, fine. Whats the super secret password then?"
            $Response = Read-Host
            if ($Response -eq "i really shouldnt be doing this") {
                <# Write-Host "Alright then, on your head be it"
                $Devices = Invoke-SQLCommand -sqlCommand "$SQLCommand" -dataSource $DataSource -database $WS1Database -Username $ReadOnlyUsername -Password $ReadOnlyPassword
                Write-Host "$(($Devices.FriendlyName).Count) devices found via SQL query" #>
                Write-Host "Nah you dont really know the super secret password, I'm not gonna do that"
                exit
            } else {
                Write-Host "I KNEW IT!!!"
                exit
            }
        } else {
            Write-Host "PHEW! That was a close one"
            exit
        }
    } else {
        exit
    }
}

$OldLocation = (Get-Location).Path

Set-Location $Location
Write-Host "You are about to attempt to upgrade the Workspace ONE client on $(($Devices.FriendlyName).Count) devices. Are you sure you want to continue?"
$Response = Read-Host -Prompt "Confirm [y/n]?"

if ($response -eq "y") {
    foreach ($Device in $Devices) {
        if ($Device.FriendlyName) {
            $Device = $Device.FriendlyName
        }
        if ($Device -notin $ExcludedDevices) {
            $Online = Test-NetConnection -ComputerName $Device -InformationLevel Quiet
            if ($Online -eq $true) {
                Write-Host "Checking WS1 version and status on $Device"
                try {
                    $OutputObject = Get-Status -Device $device

                    if (($OutputObject.Version).Count -gt 1) {
                        Write-Host "Multiple versions are installed, a manual fix will be required"
                    } else {

                        switch ($OutputObject.Version) {
                            "22.3.2.0" {
                                Write-Host "$Device has version $_ installed. Repairing installation"
                                $date = Get-Date -Format "yyyyMMdd"
                                .\psexec.exe \\$Device -s -h cmd /c "$env:WinDir\System32\msiexec.exe /f $($OutputObject.GUID) /quiet  /l*v `"C:\ProgramData\Airwatch\UnifiedAgent\Logs\InstallerRepairLog_$date.log`""
                                Write-Host "Installation repaired, copying new MSI"
                                Copy-Item -Path "$NewPath" -Destination "\\$Device\c$\temp\AirWatchAgent.msi" -Force
                                Write-Host "Running new installation"
                                .\psexec.exe \\$Device -s -h cmd /c "$env:WinDir\System32\msiexec.exe /i `"C:\temp\AirWatchAgent.msi`" /quiet  /l*v `"C:\ProgramData\Airwatch\UnifiedAgent\Logs\InstallerLog_$date.log`""
                            }
                            { ($_ -like "20.*") -or ($_ -eq "21.2.1.0") -or ($_ -eq "21.1.0.0") } {
                                Write-Host "$Device has version $_ installed. Copying old MSI to device and attempting an upgrade"
                                if (!(Test-Path "\\$Device\c$\Program Files (x86)\Airwatch\AgentUI\Update" -PathType Container)) {
                                    New-Item -Path "\\$Device\c$\Program Files (x86)\Airwatch\AgentUI\Update" -ItemType Directory
                                }
                                Copy-Item -Path "$OldPath" -Destination "\\$Device\c$\temp\AirWatchAgent.msi" -Force
                                .\psexec.exe \\$Device -s -h cmd /c "$env:WinDir\System32\msiexec.exe /i `"C:\temp\AirWatchAgent.msi`" /quiet  /l*v `"C:\ProgramData\Airwatch\UnifiedAgent\Logs\InstallerLog_$date.log`""
                                Copy-Item -Path "$NewPath" -Destination "\\$Device\c$\temp\AirWatchAgent.msi" -Force
                                Write-Host "Running new installation"
                                .\psexec.exe \\$Device -s -h cmd /c "$env:WinDir\System32\msiexec.exe /i `"C:\temp\AirWatchAgent.msi`" /quiet  /l*v `"C:\ProgramData\Airwatch\UnifiedAgent\Logs\InstallerLog_$date.log`""
                            }
                            { ($_ -lt "$Version.*") } {
                                Write-Host "$Device has version $_ installed. Copying new MSI to device and attempting an upgrade"
                                Copy-Item -Path "$NewPath" -Destination "\\$Device\c$\temp\AirWatchAgent.msi" -Force
                                Write-Host "Running new installation"
                                .\psexec.exe \\$Device -s -h cmd /c "$env:WinDir\System32\msiexec.exe /i `"C:\temp\AirWatchAgent.msi`" /quiet  /l*v `"C:\ProgramData\Airwatch\UnifiedAgent\Logs\InstallerLog_$date.log`""
                            }
                            { ($_ -ge "$Version.*") } {
                                Write-Host "$Device has version $_ installed which is greater than or equal to the version you are trying to upgrade to. No action required"
                            }
                            "" {
                                Write-Host "$Device doesnt have a functioning client, a renerol is required"
                            }
                            Default { Write-Host "Device has version $($OutputObject.Version) which is not accounted for in this script" }
                        }
                        $OutputObject = Get-Status -Device $device
                        Write-Host "Current version installed :: $($OutputObject.Version)"
                    }
                } catch {
                    $OutputObject = [PSCustomObject]@{
                        LoggedOnUser  = $_.Exception.Message
                        Version       = ""
                        BootTime      = ""
                        ServiceStatus = ""
                        Processes     = ""
                        GUID          = ""
                        DeviceName    = $Device
                    }
                }
                Export-Csv -InputObject $OutputObject -Append -Path "$scriptDirectory\Report.csv" -NoTypeInformation
            }
        }
    }
}
Set-Location $OldLocation
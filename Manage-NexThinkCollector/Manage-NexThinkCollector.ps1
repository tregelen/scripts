<#
.SYNOPSIS
    This script interacts with the NexThink collector, allowing you to start or stop it on a specified device.

.DESCRIPTION
    The script provides functionality to control the NexThink collector service. You can start or stop the collector based on your requirements.

.PARAMETER Action
    Specifies the action to perform: "start" or "stop." This parameter is mandatory.

.PARAMETER DeviceName
    Specifies the name of the device where the NexThink collector is installed. This parameter is mandatory.

.PARAMETER Import
    Specifies the CSV file of device names to import. This parameter is mandatory.

.PARAMETER Display
    Displays the results of the script at the end.

.OUTPUTS
    None

.EXAMPLE
    Start the NexThink collector on a device named "MyDevice":
    .\Manage-NexThinkCollector.ps1 -Action "start" -DeviceName "MyDevice"

.EXAMPLE
    Stop the NexThink collector on a device named "AnotherDevice":
    .\Manage-NexThinkCollector.ps1 -Action "stop" -DeviceName "AnotherDevice"

.EXAMPLE
    Stop the NexThink collector on a series of devices:
    .\Manage-NexThinkCollector.ps1 -Action "stop" -Import "C:\temp\NexThinkCollector.csv"
#>

param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Bulk')]
    [ValidateSet("start", "stop")]
    [string]$Action,
    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [string]$DeviceName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Bulk')]
    [string]$Import,
    [switch]$Display
)

$ServiceNames = @("Nexthink Coordinator", "Nexthink Service")

if ($Import) {
    try {
        $DeviceList = Import-Csv -Path "$Import"
    } catch {
        Write-Host "Unable to import the list from $Import, exiting script."
        Exit
    }
} else {
    $DeviceList = $DeviceName
}
$FullResults = @()

foreach ($Device in $DeviceList) {
    if ($Device.DeviceName) {
        $Device = $Device.DeviceName
    }

    if ($null -eq $Action) {
        Write-Host "You have not specified if you want to stop or start the collector, exiting"
    } else {
        Write-Host "Attempting to $Action the NexThink collector services on $Device"
        try {
            $Results = Invoke-Command -ComputerName $Device -ArgumentList $Action, $ServiceNames -ScriptBlock {
                param($Action, $ServiceNames)
                $Return = @()

                foreach ($ServiceName in $ServiceNames) {

                    $Status = Get-Service -Name $ServiceName | Select-Object -Property name, starttype, status

                    switch ($Action) {
                        start {
                            if (($Status.starttype).ToString().ToLower() -ne "automatic") {
                                Set-Service -Name $ServiceName -StartupType Automatic
                            }

                            if (($Status.Status).ToString().ToLower() -eq "running") {
                            } elseif (($Status.Status).ToString().ToLower() -eq "starting") {
                                Start-Sleep -Seconds 10
                            } else {
                                Start-Service -Name $ServiceName
                                Start-Sleep -Seconds 10
                            }

                        }
                        stop {
                            if (($Status.Status).ToString().ToLower() -ne "stopped") {
                                Get-Service -Name $ServiceName | Set-Service -StartupType Disabled
                                Stop-Service -Name $ServiceName -Force
                                Start-Sleep -Seconds 10
                            }
                        }
                        Default {}
                    }

                    $TempReturnStatus = Get-Service -Name $ServiceName | Select-Object -Property name, starttype, status
                    $Return += $TempReturnStatus

                }
                Write-Output -InputObject $Return
            }

            foreach ($Service in $ServiceNames) {
                $ServiceDetails = $Results | Where-Object { $_.Name -eq $Service }
                $Temp = [PSCustomObject]@{
                    DeviceName = $Device
                    Service    = $ServiceDetails.Name
                    Status     = $ServiceDetails.Status
                    StartType  = $ServiceDetails.StartType

                }
                $FullResults += $Temp
            }
        } catch {
            $ErrorResults
            Write-Host "Error: $_"
        }
    }
}

if ($Display.IsPresent()) {
    $FullResults | Format-Table
}
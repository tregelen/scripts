[CmdletBinding()]
param (
    [Parameter()]
    [String]$DeviceName,
    [switch]$Install,
    [switch]$RepairWMI,
    [switch]$Restart,
    [string]$Bulk,
    [string]$Export,
    [switch]$NoProfiles,
    [switch]$Display
)

#region Get-OnlineStatus
Function Get-OnlineStatus {
    <#
.SYNOPSIS
    The Get-OnlineStatus PowerShell function is used to determine if a specified device is currently online and available on the network. It achieves this by attempting to resolve the device's name to an IP address and then pinging the device using the Test-NetConnection cmdlet.
.DESCRIPTION

.PARAMETER DeviceName
    Specifies the name of the device to be checked for online status.
.PARAMETER Quiet
    This is an optional switch parameter that suppresses the output of the Test-NetConnection cmdlet, displaying only the status of the device instead of the full output. If the switch is not used, the full output of the Test-NetConnection cmdlet is displayed.
.PARAMETER DefaultIP
    his is an optional parameter that specifies the default IP address range to be used when resolving the device's name to an IP address. If the IP addresses returned do not fall within this range, it will not return any results. This is only used if multiple IP addresses are returned from the DNS lookup. The default value is "10.*".

.EXAMPLE
    Get-OnlineStatus [-DeviceName] <string> [-Quiet] [-DefaultIP <string>]

This example checks the online status of a device named "Computer01" and displays the output.

    Get-OnlineStatus -DeviceName "Computer01"

This example checks the online status of a device named "Server01" and suppresses the output of the Test-NetConnection cmdlet.

    Get-OnlineStatus -DeviceName "Server01" -Quiet

This example checks the online status of a device named "Printer01" using the default IP address range of "192.168.*".

    Get-OnlineStatus -DeviceName "Printer01" -DefaultIP "192.168.*"

.NOTES

#>
    Param ([string]$DeviceName,
        [switch]$Quiet,
        [string]$DefaultIP = "10.*"
    )

    Begin {
        #[string] ${CmdletName} = $MyInvocation.MyCommand.Name
        ####Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        Try {
            $TempDNSResolve = Resolve-DnsName -Name $DeviceName -ErrorAction Stop

            if (($TempDNSResolve | Where-Object { $_.Type -eq "A" }).Count -gt 1) {
                if (($TempDNSResolve | Where-Object { $_.IPAddress -like "$DefaultIP" }).Count -eq 1) {
                    [Microsoft.DnsClient.Commands.DnsRecord]$DNSResolve = $TempDNSResolve | Where-Object { $_.IPAddress -like "$DefaultIP" }
                } else {
                    [Microsoft.DnsClient.Commands.DnsRecord]$DNSResolve = ($TempDNSResolve | Where-Object { $_.IPAddress -like "$DefaultIP" })[0]
                }
            } else {
                [Microsoft.DnsClient.Commands.DnsRecord]$DNSResolve = $TempDNSResolve
            }

            if ($Quiet) {
                [boolean]$OnlineStatus = Test-NetConnection -ComputerName $DNSResolve.Name -InformationLevel Quiet
            } else {
                [Object]$OnlineStatus = Test-NetConnection -ComputerName $DNSResolve.Name
            }
        } catch {
            $message = $_
            [string]$OnlineStatus = "DNS Error"
            Write-Host "$($DeviceName): $message" -ForegroundColor Red
        }

        Write-Output -InputObject $OnlineStatus
    }
    End {
        ####Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-OnlineStatus
#region Get-Statistics
Function Get-Statistics {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Verb-Noun -Parameter $Value
.NOTES

#>
    Param ($Device
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        ####Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $Results = Invoke-Command -ComputerName $Device -ScriptBlock {
            [datetime]$Global:Today = Get-Date
            #region Get-ADSite
            Function Get-ADSite {
                <#
                    .SYNOPSIS
                        Attempts to get the current AD site first using .Net, if that doesn't work it will attempt to retrieve it using 'nltest'.
                        If it is still unable to retrieve the ADsite using either of those methods it will return 'error' as the AD site.

                    .EXAMPLE
                        $ADSite = Get-ADSite
                    .NOTES
                        'The long way' method using DHCP lookups was taking too long and was unreliable to function in the agency so was removed for efficiency.
                    #>
                Param (
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    ##Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {

                    try {
                        Write-Host "Attempting to get AD site using .Net"
                        [string]$ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
                    } catch {
                        try {
                            Write-Host "Unable to get AD site using .Net. Trying with 'nltest'"
                            [string]$ADSite = (nltest /server:$ENV:COMPUTERNAME /dsgetsite)[0]
                        } catch {
                            Write-Host "Unable to get AD site using any method. Writing to registry"
                            $ADSite = "Error"
                        }
                    }

                    Write-Host "AD Site located: $ADSite"
                    Write-Output -InputObject $ADSite
                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-ADSite
            #region Get-DiskSpace
            Function Get-DiskSpace {
                <#
                .DESCRIPTION
                    Gets the total size of the disk, including free space and free percentage
                .PARAMETER Drive
                    Used to return just a single drive, if not included it will return all local drives
                .EXAMPLE
                    Get-DiskSpace -Drive C
                .NOTES
                    Will only return local drives, network and USB drives are not included
                #>
                Param ([string]$Drive)

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    $Disks = @()
                    $DiskObjects = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" }
                    $DiskObjects | ForEach-Object {
                        $Disk = New-Object PSObject -Property @{
                            Name           = $_.DeviceID
                            Capacity       = [math]::Round($_.Size / 1GB, 2)
                            FreeSpace      = [math]::Round($_.FreeSpace / 1GB, 2)
                            FreePercentage = [math]::Round($_.FreeSpace / $_.Size * 100, 1)
                        }
                        $Disks += $Disk
                    }

                    if ($Drive) {
                        # Format Drive variable
                        if ($Drive.ToUpper() -eq "HOME") {
                            $Drive = $ENV:HOMEDRIVE
                        } else {
                            # Check for trailing slash and remove
                            if ($Drive.Substring($Drive.Length - 1, 1) -eq "\") {
                                $Drive = $Drive.Substring(0, $Drive.Length - 1)
                            }
                            # Check for trailing colon and add if missing
                            if ($Drive.Substring($Drive.Length - 1, 1) -ne ":") {
                                $Drive = "$($Drive):"
                            }
                        }
                        $ReturnObject = $($Disks | Where-Object { $_.Name -eq "$($Drive.ToUpper())" })
                    } else {
                        $ReturnObject = $Disks
                    }

                    if ($null -eq $ReturnObject) {
                        $ReturnObject = "Nothing to return"
                    }
                    Write-Output -InputObject $ReturnObject
                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-DiskSpace

            #region Get-WS1Processes
            Function Get-WS1Processes {
                <#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE
    Get-WS1Processes -Parameter $Value
.NOTES

#>
                Param ([switch]$RestartAWipc
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    $Processes = Get-Process -IncludeUserName | Where-Object { ($_.Name -like "TaskScheduler") -OR ($_.Name -like "AwWindowsipc") -OR ($_.Name -like "AW.WinPC.Updater") }

                    if (($Processes | Where-Object { $_.Name -like "AwWindowsipc" }).Username -eq $LoggedOnUser) {
                        $AwWindowsipc = "Running as logged on user"
                    } elseif (!($Processes | Where-Object { $_.Name -like "AwWindowsipc" })) {
                        $AwWindowsipc = "Not running"
                        if ($RestartAWipc.IsPresent) {
                            $Processes | Where-Object { $_.Name -like "AwWindowsipc" } | Stop-Process -Force
                            $Processes | Where-Object { $_.Name -like "TaskScheduler" } | Stop-Process -Force
                            Start-Sleep -Seconds 30
                            $AwWindowsipc = (Get-WS1Processes).AwWindowsipc
                        }
                    } elseif (($Processes | Where-Object { $_.Name -like "AwWindowsipc" }).Username -ne $LoggedOnUser) {
                        $AwWindowsipc = "Running as a different user :: $(($Processes | Where-Object { $_.Name -like "AwWindowsipc" }).Username)"

                        if ($RestartAWipc.IsPresent) {
                            $Processes | Where-Object { $_.Name -like "AwWindowsipc" } | Stop-Process -Force
                            $Processes | Where-Object { $_.Name -like "TaskScheduler" } | Stop-Process -Force
                            Start-Sleep -Seconds 30
                            $AwWindowsipc = (Get-WS1Processes).AwWindowsipc
                        }
                    } else {
                        $AwWindowsipc = "Error"
                    }

                    if (($Processes | Where-Object { $_.Name -like "TaskScheduler" }).Username -eq "NT Authority\System") {
                        $TaskScheduler = "Running"
                    } else {
                        $TaskScheduler = "Not running"
                    }

                    $ReturnObject = [PSCustomObject]@{
                        AwWindowsipc  = $AwWindowsipc
                        TaskScheduler = $TaskScheduler
                    }

                    Write-Output -InputObject $ReturnObject
                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-WS1Processes
            #region Get-MSIEvents
            Function Get-MSIEvents {
                <#
.SYNOPSIS
Retrieves logon and logoff events from the Windows event logs.

.DESCRIPTION
This function retrieves logon and logoff events from the Windows event logs using the Microsoft-Windows-Winlogon provider. It specifically looks for event IDs 7001 (logon) and 7002 (logoff) and extracts information about the time of the event, the user who logged on or off, and the type of event (logon or logoff).

.EXAMPLE
Get-LogonEvents

Retrieves all logon and logoff events from the Windows event logs and outputs them as objects.

.NOTES
This function provides a convenient way to access logon and logoff events from the Windows event logs within PowerShell scripts or functions. It can be useful for monitoring user activity or troubleshooting login-related issues.

#>
                Param (
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    Write-Host "Getting all MSI events. This could take a while."

                    $AllMSIEvents = @()
                    $startDate = (Get-Date).AddDays(-7)
                    $enddate = Get-Date
                    $MSIEvents = Get-WinEvent -ProviderName MSIInstaller | Where-Object { $_.Timecreated -ge $startDate -and $_.Timecreated -lt $endDate }

                    foreach ($Event in $MSIEvents) {
                        $TempLogonEvents = [PSCustomObject]@{
                            Time = $Event.TimeCreated
                            Type = $Event.Message
                        }

                        $AllMSIEvents += $TempLogonEvents

                    }

                    Write-Output -InputObject $AllMSIEvents

                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-MSIEvents
            #region Get-LogonEvents
            Function Get-LogonEvents {
                <#
.SYNOPSIS
Retrieves logon and logoff events from the Windows event logs.

.DESCRIPTION
This function retrieves logon and logoff events from the Windows event logs using the Microsoft-Windows-Winlogon provider. It specifically looks for event IDs 7001 (logon) and 7002 (logoff) and extracts information about the time of the event, the user who logged on or off, and the type of event (logon or logoff).

.EXAMPLE
Get-LogonEvents

Retrieves all logon and logoff events from the Windows event logs and outputs them as objects.

.NOTES
This function provides a convenient way to access logon and logoff events from the Windows event logs within PowerShell scripts or functions. It can be useful for monitoring user activity or troubleshooting login-related issues.

#>
                Param (
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    #Write-Log -Message "Getting all Logon events. This could take a while." -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

                    $AllLogonEvents = @()
                    #$WinEvents = Get-WinEvent -ProviderName Microsoft-Windows-Winlogon | Where-Object { ($_.Id -eq 7001) -or ($_.Id -eq 7002) }
                    $WinEvents = Get-WinEvent -FilterHashtable @{ LogName = "System"; ID = 7001, 7002 }
                    foreach ($Event in $WinEvents) {

                        [xml]$EventXML = $Event.ToXml()
                        switch ($EventXML.Event.System.EventID) {
                            7001 {
                                $ID = 7001
                                $type = "Logon"
                            }
                            7002 {
                                $ID = 7002
                                $type = "Logoff"
                            }
                            Default {}
                        }

                        $UserSID = $Eventxml.Event.EventData.Data[1].'#text'

                        if (($UserSID -eq "sstpsvc") -or ($Null -eq $UserSID)) {
                            Continue
                        }

                        Try {
                            $User = (New-Object System.Security.Principal.SecurityIdentifier $UserSID).Translate([System.Security.Principal.NTAccount]).Value
                        } Catch {
                            $User = "Unable to translate user ID"
                        }

                        # Convert the string to a date because its stupid
                        $DateSplit = ($EventXML.Event.System.TimeCreated.SystemTime).Split("-").Split("T").Split(":").Split(".")
                        $DateYear = $DateSplit[0]
                        $DateMonth = $DateSplit[1]
                        $DateDay = $DateSplit[2]
                        $DateHour = $DateSplit[3]
                        $DateMinute = $DateSplit[4]
                        $DateSecond = $DateSplit[5]

                        $DateTime = Get-Date -Year $DateYear -Month $DateMonth -Day $DateDay -Hour $DateHour -Minute $DateMinute -Second $DateSecond

                        $TempLogonEvents = [pscustomobject]@{
                            TimeCreated = $DateTime
                            ID          = $ID
                            Type        = $type
                            UserSID     = $UserSID
                            UserName    = $User
                        }
                        if ($User -notin ($AllLogonEvents | Where-Object { $_.UserName -eq $User }).Username) {
                            $AllLogonEvents += $TempLogonEvents
                        }

                    }

                    Write-Output -InputObject $AllLogonEvents

                }

                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-LogonEvents

            Function Format-ProfileData {
                <#
.SYNOPSIS
Formats profile data into a custom object for easier handling and manipulation.

.DESCRIPTION
This function takes various parameters related to a user profile and formats them into a custom object. The parameters include the username, domain, security identifier (SID), profile path, size in megabytes, last use time retrieved from CIM, last use time retrieved from the registry, event log date, event log type, last logon time, profile age, and action to be taken.

.EXAMPLE
Format-ProfileData -username "JohnDoe" -Domain "Contoso" -SID "S-1-5-21-3623811015-3361044348-30300820-1013" -Path "C:\Users\JohnDoe" -SizeMB 1024 -CIMLastUseTime "2023-05-15 08:30:00" -RegistryLastUseTime "2023-05-14 20:45:00" -EventLogDate "2023-05-14 10:00:00" -EventLogType "Logoff" -LastLogon "2023-05-13 18:00:00" -Action "Delete" -ProfileAge 30

Formats profile data for the user "JohnDoe" into a custom object with specified parameters.

.NOTES
This function is useful for organizing and standardizing profile-related data within PowerShell scripts or functions. It creates a structured object containing essential information about user profiles, facilitating easier handling and manipulation of profile data.

#>
                Param ($username,
                    $Domain,
                    $SID,
                    $Path,
                    $SizeMB,
                    $CIMLastUseTime,
                    $RegistryLastUseTime,
                    $EventLogDate,
                    $EventLogType,
                    $LastLogon,
                    $Action,
                    $ProfileAge
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    $ReturnObject = [PSCustomObject]@{
                        Username            = if ($username) { $username }else { $null }
                        Domain              = if ($Domain) { $Domain }else { $null }
                        SID                 = if ($SID) { $SID }else { $null }
                        Path                = if ($Path) { $Path }else { $null }
                        SizeMB              = if ($SizeMB) { $SizeMB }else { $null }
                        CIMLastUseTime      = if ($CIMLastUseTime) { $CIMLastUseTime }else { $null }
                        RegistryLastUseTime = if ($RegistryLastUseTime) { $RegistryLastUseTime }else { $null }
                        EventLogDate        = if ($EventLogDate) { $EventLogDate }else { $null }
                        EventLogType        = if ($EventLogType) { $EventLogType }else { $null }
                        LastLogon           = if ($LastLogon) { $LastLogon }else { $null }
                        ProfileAge          = if ($ProfileAge) { $ProfileAge }else { $null }
                        Action              = if ($Action) { $Action }else { $null }
                        Device              = $null
                    }

                    Write-Output -InputObject $ReturnObject
                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }

            #region Get-UserName
            Function Get-UserName {
                <#
.SYNOPSIS
Retrieves the username associated with a given security identifier (SID).

.DESCRIPTION
This function takes a security identifier (SID) as input and returns the corresponding username. Optionally, it can also include the domain name along with the username.

.PARAMETER Sid
Specifies the security identifier (SID) for which to retrieve the username.

.PARAMETER Domain
Indicates whether to include the domain name in the output. By default, only the username is returned.

.EXAMPLE
Get-UserName -Sid "S-1-5-21-397955417-626881126-188441444-500"

Retrieves the username associated with the specified SID.

.EXAMPLE
Get-UserName -Sid "S-1-5-21-397955417-626881126-188441444-500" -Domain

Retrieves the username along with the domain name associated with the specified SID.

.NOTES
This function relies on the .NET classes System.Security.Principal.SecurityIdentifier and System.Security.Principal.NTAccount to perform the SID-to-username translation. It outputs a custom object containing the username and optionally the domain name.

#>
                Param (
                    [string]$sid,
                    [switch]$Domain
                )

                Begin {
                    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
                }
                Process {
                    $UserSID = New-Object System.Security.Principal.SecurityIdentifier ($SID)
                    $objUser = $UserSID.Translate( [System.Security.Principal.NTAccount])
                    if ($domain -eq $false) {
                        $ReturnObject = [PSCustomObject]@{
                            Username   = $objUser.Value.Substring($objUser.Value.IndexOf("\") + 1)
                            DomainName = ""
                        }
                    } else {
                        $ReturnObject = [PSCustomObject]@{
                            Username   = $objUser.Value.Substring($objUser.Value.IndexOf("\") + 1)
                            DomainName = $objUser.Value.Substring(0, $objUser.Value.IndexOf("\"))
                        }
                    }

                    Write-Output -InputObject $ReturnObject
                }
                End {
                    #Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
                }
            }
            #endregion Get-UserName

            try {
                $LastShutdown = Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074 } -MaxEvents 1
                $LastShutdownTime = $LastShutdown.TimeCreated
                $MessageSearch = "on behalf of user"
                $MessageSearchEnd = "for the following reason"
                $index = $LastShutdown.Message.IndexOf($MessageSearch)
                $indexEnd = $LastShutdown.Message.IndexOf($MessageSearchEnd)
                $LastShutdownUser = ($LastShutdown.Message.Substring($index + $MessageSearch.Length, $indexEnd - $index - $MessageSearch.Length)).Trim()
            } catch {
                $LastShutdownTime = "Error"
                $LastShutdownUser = "Error"
            }



            $excludedUsernames = @("Administrator", "Public")

            $ADSite = Get-ADSite
            $MSIEventsReport = Get-MSIEvents
            $AllUserProfilesCIM = Get-CimInstance -ClassName Win32_UserProfile -Filter "Special='False'"
            $AllUserProfilesRegistry = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object { Get-ItemProperty $_.PSPath }
            $LogonEvents = Get-LogonEvents
            $AllUserProfilesFileSystem = Get-ChildItem "$ENV:SystemDrive\Users" | Where-Object { $_.Name -notin $excludedUsernames }

            $ProfileList = @()
            foreach ($CIMProfile in $AllUserProfilesCIM) {
                $CIMLastUseTime = $CIMProfile.LastUseTime
                $ProfileData = Format-ProfileData -SID $CIMProfile.SID -Path $CIMProfile.LocalPath -CIMLastUseTime $CIMLastUseTime

                $ProfileList += $ProfileData
            }

            foreach ($RegistryProfile in $AllUserProfilesRegistry) {

                $RegistrySID = $RegistryProfile.PSChildName

                if ($ExcludedLocalSIDs -contains $RegistrySID) {
                    #Write-Log -Message "Skipping Registry entry $($RegistryProfile.PSChildName) as it is in the exclusion list" -Component ${CmdletName}
                } else {
                    #Write-Log -Message "Adding Registry entry $($RegistryProfile.PSChildName)" -Component ${CmdletName}
                    $ProfileLoadHighDec = $RegistryProfile.LocalProfileLoadTimeHigh
                    $ProfileLoadLowDec = $RegistryProfile.LocalProfileLoadTimeLow

                    $ProfileUnLoadHighDec = $RegistryProfile.LocalProfileUnLoadTimeHigh
                    $ProfileUnLoadLowDec = $RegistryProfile.LocalProfileUnLoadTimeLow

                    # Convert Decimal to Hex string
                    # Example:  ProfileLoadHighHex = 01d8fd57 / ProfileLoadLowHex = 86b1d3bc
                    $ProfileLoadHighHex = [System.Convert]::ToString($ProfileLoadHighDec, 16)
                    $ProfileLoadLowHex = [System.Convert]::ToString($ProfileLoadLowDec, 16)

                    $ProfileUnLoadHighHex = [System.Convert]::ToString($ProfileUnLoadHighDec, 16)
                    $ProfileUnLoadLowHex = [System.Convert]::ToString($ProfileUnLoadLowDec, 16)

                    # Concatenate hex strings
                    # Example: 01d8fd5786b1d3bc
                    $ProfileLoadHexJoined = -join ($ProfileLoadHighHex, $ProfileLoadLowHex)
                    $ProfileUnloadHexJoined = -join ($ProfileUnLoadHighHex, $ProfileUnLoadLowHex)

                    # Convert to DateTime format
                    # Example: 11/21/2022 03:15:37
                    $TimestampIntLoad = [Convert]::ToInt64($ProfileLoadHexJoined, 16)
                    $TimestampIntUnLoad = [Convert]::ToInt64($ProfileUnloadHexJoined, 16)

                    $ProfileLoadDate = [DateTime]::FromFileTimeutc($TimestampIntLoad)
                    $ProfileUnLoadDate = [DateTime]::FromFileTimeutc($TimestampIntUnLoad)

                    if ($ProfileLoadDate -lt $ProfileUnLoadDate) {
                        $RegistryProfileLoad = $ProfileUnLoadDate
                    } else {
                        $RegistryProfileLoad = $ProfileLoadDate
                    }

                    $ProfileData = Format-ProfileData -SID $RegistrySID -Path $RegistryProfile.ProfileImagePath -RegistryLastUseTime ($RegistryProfileLoad)

                    if ($ProfileList.SID -contains $RegistrySID) {
                ($ProfileList | Where-Object { $_.SID -eq $RegistrySID }).RegistryLastUseTime = $RegistryProfileLoad
                    } elseif ($ProfileList.Path -contains $RegistryProfile.ProfileImagePath) {
                ($ProfileList | Where-Object { $_.Path -eq $RegistryProfile.ProfileImagePath }).RegistryLastUseTime = $RegistryProfileLoad
                    } else {
                        $ProfileList += $ProfileData
                    }
                }
            }

            foreach ($FileSystemProfile in $AllUserProfilesFileSystem) {
                if ($ProfileList.Path -notcontains $FileSystemProfile.FullPath) {
                    $ProfileData = Format-ProfileData -Path $FileSystemProfile.FullPath
                    $ProfileList += $ProfileData
                }
            }
            foreach ($Profile in $ProfileList) {
                if ($null -ne $Profile.SID) {
                    try {
                        $Username = Get-UserName -SID $Profile.SID -Domain

                    ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).Username = "$($username.Username)"
                    ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).Domain = "$($username.DomainName)"
                    } catch {
                    ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).Username = "Unable to retrieve username"
                    }
                }
            }

            foreach ($LogonEvents in $AllLogonEvents) {
                $Domain = $LogonEvents.Username.Split("\")[0]
                $Username = $LogonEvents.Username.Split("\")[1]
                $LogEventDate = $LogonEvents.TimeCreated
                #Write-Log -Message "Adding logon event for $Username :: $LogEventDate" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

                if ($ProfileList.Username -notcontains $Username) {
                    #Write-Log -Message "$Username has a logon event, but does not currently have a profile. Skipping event" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"
                } else {
                    try {
                    ($ProfileList | Where-Object { ($_.Username -eq $Username) -and ($_.Domain -eq $Domain) }).EventLogDate = $LogEventDate
                    ($ProfileList | Where-Object { ($_.Username -eq $Username) -and ($_.Domain -eq $Domain) }).EventLogType = $LogonEvents.Type
                    } catch {
                        #Write-Log -Message "Unable to add event log and event type to $Username" -Severity 2 -Component ${CmdletName}
                    }
                }
            }
            $ProfileList | ForEach-Object {$_.Device = $ENV:Computername}

            $ExcludedDomains = @("$ENV:ComputerName", "NT Authority")

            $ProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
            $CurrentBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
            $UBR = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
            $OSVersion = $CurrentBuild + "." + $UBR
            $SFDAgentVersion = (Get-Item "C:\Program Files\VMware\SfdAgent\VMware.Hub.SfdAgent.DeployCmd.exe").VersionInfo.FileVersion
            switch ($CurrentBuild) {
                19045 { $WindowsVersion = "22H2" }
                19044 { $WindowsVersion = "21H2" }
                19043 { $WindowsVersion = "21H1" }
                19042 { $WindowsVersion = "20H2" }
                19041 { $WindowsVersion = "2004" }
                18363 { $WindowsVersion = "1909" }
                18362 { $WindowsVersion = "1903" }
                17763 { $WindowsVersion = "1809" }
                17134 { $WindowsVersion = "1803" }
                16299 { $WindowsVersion = "1709" }
                15063 { $WindowsVersion = "1703" }
                14393 { $WindowsVersion = "1607" }
                10586 { $WindowsVersion = "1511" }
                10240 { $WindowsVersion = "1507" }

                22631 { $WindowsVersion = "23H2" }
                22621 { $WindowsVersion = "22H2" }
                22000 { $WindowsVersion = "21H2" }

                Default {}
            }

            $BootTime = (Get-WmiObject -Class Win32_OperatingSystem | Select-Object @{LABEL = 'LastBootUpTime'; EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } }).LastBootUpTime
            try {
                $ServiceStatus = (Get-Service -Name "AirWatchService" -ErrorAction SilentlyContinue).Status
            } catch {
                $ServiceStatus = "Not Running"
            }
            $LoggedOnUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object username).Username
            $AWProcesses = Get-WS1Processes -Restart

            try {

                $HealthCheckReg = "HKLM:\SOFTWARE\HealthCheck"
                $ProfileCheakReg = "$HealthCheckReg\ProfileCleanup"
                $DiskCheckReg = "$HealthCheckReg\DiskCleanup"
                if (Test-Path -Path $HealthCheckReg) {
                    try {
                        $WorkstationHealthCheckVersion = (Get-ItemProperty "$HealthCheckReg" -Name Version -ErrorAction SilentlyContinue).Version
                    } catch {
                        $WorkstationHealthCheckVersion = $null
                    }
                }

                if (Test-Path -Path $ProfileCheakReg) {
                    try {
                        $ProfileCleanupLastRun = (Get-ItemProperty "$ProfileCheakReg" -Name LastRun -ErrorAction SilentlyContinue).LastRun
                        if ($ProfileCleanupLastRun.Length -le 0) {
                            $ProfileCleanupLastRun = (Get-ItemProperty "$ProfileCheakReg" -Name Date -ErrorAction SilentlyContinue).Date
                        }
                    } catch {
                        $ProfileCleanupLastRun = $null
                    }
                    try {
                        $ProfileCleanupTotalClearedSpace = (Get-ItemProperty "$ProfileCheakReg" -Name TotalClearedSpace -ErrorAction SilentlyContinue).TotalClearedSpace
                    } catch {
                        $ProfileCleanupTotalClearedSpace = $null
                    }
                    try {
                        $ProfileCleanupLastClearedSpace = (Get-ItemProperty "$ProfileCheakReg" -Name LastClearedSpace -ErrorAction SilentlyContinue).LastClearedSpace
                    } catch {
                        $ProfileCleanupLastClearedSpace = $null
                    }
                }

                if (Test-Path -Path $DiskCheckReg) {
                    try {
                        $DiskCleanupLastRun = (Get-ItemProperty "$DiskCheckReg" -Name LastRun -ErrorAction SilentlyContinue).LastRun
                        if ($DiskCleanupLastRun.Length -le 0) {
                            $DiskCleanupLastRun = (Get-ItemProperty "$DiskCheckReg" -Name Date -ErrorAction SilentlyContinue).Date
                        }
                    } catch {
                        $DiskCleanupLastRun = $null
                    }
                    try {
                        $DiskCleanupTotalClearedSpace = (Get-ItemProperty "$DiskCheckReg" -Name TotalClearedSpace -ErrorAction SilentlyContinue).TotalClearedSpace
                    } catch {
                        $DiskCleanupTotalClearedSpace = $null
                    }
                    try {
                        $DiskCleanupLastClearedSpace = (Get-ItemProperty "$DiskCheckReg" -Name LastClearedSpace -ErrorAction SilentlyContinue).LastClearedSpace
                    } catch {
                        $DiskCleanupLastClearedSpace = $null
                    }
                }
            } catch {
                $WorkstationHealthCheckVersion = "Error"
                $ProfileCleanupLastRun = "Error"
                $ProfileCleanupTotalClearedSpace = "Error"
                $ProfileCleanupLastClearedSpace = "Error"
                $DiskCleanupLastRun = "Error"
                $DiskCleanupTotalClearedSpace = "Error"
                $DiskCleanupLastClearedSpace = "Error"
            }


            $WS1QueuePath = "HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Queue"

            if (Test-Path -Path $WS1QueuePath) {
                $WS1Queue = Get-ChildItem "$WS1QueuePath"
                $WS1QueueLength = $WS1Queue.count
            } else {
                $WS1QueueLength = "Not present"
            }
            $CleanWS1Queue = $true
            if (($WS1QueueLength -gt 50) -and $CleanWS1Queue -eq $true) {
                Remove-Item -Path "$WS1QueuePath" -Recurse -Force
            }


            $TempDiskStatistics = @()
            $TempDiskStatistics = Get-DiskSpace -Drive $Drive

            [double]$DiskFreePercentage = $TempDiskStatistics.FreePercentage
            [double]$DiskFreeSpace = $TempDiskStatistics.FreeSpace
            [double]$DiskCapacity = $TempDiskStatistics.Capacity

            $Apps = @()
            $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
            $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" # 64 Bit
            $temp = ($Apps | Where-Object { $_.DisplayName -like "*Workspace ONE Intelligent Hub Installer*" })
            $ReturnVersion = $temp.DisplayVersion

            $ReturnObject = [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                ADSite              = $ADSite
                WindowsProduct      = $ProductName
                OSVersion           = $OSVersion
                WindowsVersion      = $WindowsVersion
                LastShutdownTime    = $LastShutdownTime
                LastShutdownUser    = $LastShutdownUser
                BootTime            = $BootTime
                ServiceStatus       = $ServiceStatus
                LoggedOnUser        = $LoggedOnUser
                AwWindowsIPC        = $AWProcesses.AwWindowsipc
                TaskScheduler       = $AWProcesses.TaskScheduler
                WS1AgentVersion     = $ReturnVersion
                WS1QueueLength      = $WS1QueueLength
                HealthCheckVersion  = $WorkstationHealthCheckVersion
                ProfileLastRun      = $ProfileCleanupLastRun
                ProfileTotalClean   = $ProfileCleanupTotalClearedSpace
                ProfileLastClean    = $ProfileCleanupLastClearedSpace

                DiskLastRun         = $DiskCleanupLastRun
                DiskTotalClean      = $DiskCleanupTotalClearedSpace
                DiskLastClean       = $DiskCleanupLastClearedSpace

                DiskSpaceFree       = $DiskFreeSpace
                DiskSpacePercentage = $DiskFreePercentage
                DiskSpaceCapacity   = $DiskCapacity

                MSIInstaller        = $MSIEventsReport.count
                SFDAgent            = $SFDAgentVersion
                Profiles            = $ProfileList | Where-Object { $_.Domain -notin $ExcludedDomains }
            }

            Write-Output -InputObject $ReturnObject
        }

        Write-Output $Results

    }
    End {
        ####Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-Statistics

if ($Bulk -eq "") {
    $DeviceList = $DeviceName
} else {
    $DeviceList = Import-Csv -Path $Bulk
}
$FullResults = @()
foreach ($Device in $DeviceList) {
    if ($null -ne $Device.DeviceName) {
        $Device = $Device.DeviceName
    }
    $Online = Get-OnlineStatus -DeviceName $Device

    if ($Online.PingSucceeded -eq $True) {
        Write-Host "$Device is online, attempting to gather information"
        $Results = Get-Statistics -Device $Device
        $FulLResults += $Results
        if ($Export) {
            $Results | Select-Object -Property * | Export-Csv -Path $Export -NoTypeInformation -Append
        } elseif ($Display -eq $true) {
            $Results | Select-Object -Property UserProfiles -ExcludeProperty UserProfiles | Format-List
        }

    }

}


foreach ($Result in $FullResults) {
    <# $currentItemName is the current item #>
}
$FullResults.Profiles

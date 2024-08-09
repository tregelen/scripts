<#
.SYNOPSIS
    Script that runs at 6 am-ish that runs through a set of health check steps
.DESCRIPTION
    Performs the following checks

    Bitlocker key is uploaded to AD (incorporate the existing bitlocker script)
    Clean user profiles older than X days
    Check disk space, clear space from specified locations

.OUTPUTS
    Log file stored in C:\Windows\Logs\Scripts\Workstation-HealthCheck.log
.NOTES

    Version:        1.24.03.1
    Author:         Aaron Whittaker
    Creation Date:  01/03/2024
    Purpose/Change:
    Revised versioning. Now 'Major.Year.Month.Increment'
    Incorporated the liteDB database into the script to replace the registry as the internal database.
    Incorporated the registry values for LocalProfileUnloadTimeHigh and LocalProfileUnoloadTimeLow as an additional data point for calculating the age of the profiles

    Version:        1.0.11.4
    Author:         Aaron Whittaker
    Creation Date:  23/06/2023
    Purpose/Change:
    Fixed a typo in the log that was annoying me

    Version:        1.0.11.2
    Author:         Aaron Whittaker
    Creation Date:  08/06/2023
    Purpose/Change:
    included more error handling for APIs not returning

    Version:        1.0.11.1
    Author:         Aaron Whittaker
    Creation Date:  19/05/2023
    Purpose/Change:
    Updated defaults from 90 days to 30 days to not rely on the group policy
    Increased logging to assist remote/on site teams with troubleshooting
    Removed some bottlenecks to increase the efficiency of the script, reducing the time taken to run
    Increased the accuracy of the calculations for the amount of space saved
    Added in handling of orphaned profiles

    Version:        1.0.10.3
    Author:         Aaron Whittaker
    Creation Date:  06/03/2023
    Purpose/Change: Added in error handling for user accounts that do not have every piece of date information

    Version:        1.0.10
    Author:         Aaron Whittaker
    Creation Date:  21/02/2023
    Purpose/Change: Reenabled the profile clean up

    Version:        1.0.3
    Author:         Aaron Whittaker
    Creation Date:  15/11/2022
    Purpose/Change: Added timeout for cleanmgr

    Version:        1.0.2
    Author:         Aaron Whittaker
    Creation Date:  09/11/2022
    Purpose/Change: Added Bitlocker
                    Removed testing components
                    Added more logging for errors

    Version:        1.0.0
    Author:         Aaron Whittaker
    Creation Date:  08/11/2022
    Purpose/Change: Initial script development

.EXAMPLE
    Workstation-HealthCheck.ps1 -RunMode Daily
        Runs the script in daily mode

    Workstation-HealthCheck.ps1 -RunMode First-Run
        Runs the script for the first time, setting up defaults
#>
##*=============================================
##* VARIABLE DECLARATION
##*=============================================

[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory = $false)]
    [ValidateSet("Daily", "Logon", "Logoff", "Startup", "Event", "First-Run")]
    [string]$RunMode,
    [int]$EventID,
    [Parameter(Mandatory = $false)]
    [ValidateSet("SCCM", "WS1", "Intune", "SCCMWS1", "SCCMIntune")]
    [string]$Management
)
#region VariableDeclaration

#region Version
[version]$ScriptVersion = "1.24.06.1"
#endregion Version

##* Do not modify section below
[string]$scriptDirectory = $PSScriptRoot
[string]$Resources = "$scriptDirectory\Resources"
[string]$Global:InvokingScriptFileName = $PSCommandPath.Replace("$PSScriptRoot\", $null)
[Boolean]$DisableLogging = $False
[decimal]$LogMaxSize = 10
[string]$Global:ScriptSection = "Initalisation"
[string]$LogStyle = "CMTrace"
[boolean]$CompressLogs = $false
[string]$LogTempFolder = "$ENV:Temp"
[string]$LogDir = "$ENV:ProgramData\Logs\Scripts"
[boolean]$LogWriteToHost = $true
[boolean]$LogDebugMessage = $false
[string]$DateFormat = "yyyy-MM-dd"
[datetime]$Global:Today = Get-Date
[string]$Global:TodayString = Get-Date -Format $DateFormat
[int32]$mainExitCode = 0
[string]$DefaultDatabasePath = "$Resources\Database\$($InvokingScriptFileName.Replace(".ps1",".db"))"
[int32]$RestMethodTimeout = 180
[int32]$DefaultAPIPageSize = 500
[string]$DatabaseConnectionCreds = ""
[int32]$DeviceAPICheckInterval = 30

##* Do not modify section above

#region For Testing
[bool]$isTesting = $true

if ($isTesting -eq $true) {
    [string]$scriptDirectory = "C:\Program Files\Workstation Health Check"
    [string]$Global:InvokingScriptFileName = "Workstation-HealthCheck.ps1"
    [string]$Resources = "$scriptDirectory\Resources"
    if ($null -eq $RunMode) {
        [string]$RunMode = "Daily"
    }
    [string]$DefaultDatabasePath = "$Resources\Database\$($InvokingScriptFileName.Replace(".ps1",".db"))"
}
#endregion For Testing

#endregion VariableDeclaration
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings

#region Add-DatabaseEntry
Function Add-DatabaseEntry {
    <#
.SYNOPSIS
    Adds one or more entries to a LiteDB database.

.DESCRIPTION
    This function adds one or more entries to a specified collection in a LiteDB database.

.PARAMETER Database
    Specifies the LiteDB database object.

.PARAMETER CollectionName
    Specifies the name of the collection in which the entries will be added.

.PARAMETER Data
    Specifies the data to be added as new entries in the collection.
    This parameter can accept a single entry or an array of entries.

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $entryData = @{
        "Name" = "John Doe"
        "Age"  = 30
        "City" = "New York"
    }
    Add-DatabaseEntry -Database $database -CollectionName "Users" -Data $entryData

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $multipleEntries = @(
        @{ "Name" = "Alice"; "Age" = 25; "City" = "London" },
        @{ "Name" = "Bob"; "Age" = 35; "City" = "Paris" }
    )
    Add-DatabaseEntry -Database $database -CollectionName "Users" -Data $multipleEntries

.NOTES

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,
        [Parameter(Mandatory = $true)]
        [string]$CollectionName,
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    Begin {
        # Get the current cmdlet name
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        # Write function header
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }

    Process {
        try {

            # Get the collection
            $collection = $Database.GetCollection($CollectionName, [LiteDB.BsonAutoId]::Int64)

            # Add each entry to the collection
            foreach ($entry in $Data) {
                $BSONMapper = [LiteDB.BSONMapper]::New()

                $collection.Insert($BSONMapper.ToDocument($Entry)) | Out-Null
            }

            <#             Write-Output "Entries added to collection '$CollectionName' in the LiteDB database."
 #>        
        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to add entries to the LiteDB database. $_" -Severity 3 -Component ${CmdletName}
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}

#endregion Add-DatabaseEntry

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
    [CmdletBinding()]
    Param ([string]$DeviceName,
        [switch]$Quiet,
        [string]$DefaultIP = "10.*"
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        Try {
            $TempDNSResolve = Resolve-DnsName -Name $DeviceName -ErrorAction Stop

            if (($TempDNSResolve | Where-Object { $_.Type -eq "A" }).Count -gt 1) {
                $DNSResolve = $TempDNSResolve | Where-Object { $_.IPAddress -like "$DefaultIP" }
            } else {
                $DNSResolve = $TempDNSResolve
            }

            if ($Quiet) {
                $OnlineStatus = Test-NetConnection -ComputerName $DNSResolve.Name -InformationLevel Quiet
            } else {
                $OnlineStatus = Test-NetConnection -ComputerName $DNSResolve.Name
            }
        } catch {
            $message = $_
            $OnlineStatus = "DNS Error"
            Write-Log -Message "$($DeviceName): $message" -Severity 3 -Component ${CmdletName}
        }

        Write-Output -InputObject $OnlineStatus
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-OnlineStatus

#region Clear-Folder
Function Clear-Folder {
    <#
.SYNOPSIS
Removes files and folders from the specified path that match the age or force criteria.

.DESCRIPTION
The Clear-Folder function removes all files and folders that match the specified criteria from the given file path. If the 'Age' parameter is provided, the function removes all files and folders that are older than the specified age. If the 'Force' switch is used, the function removes all files and folders without prompting for confirmation.

.PARAMETER FolderPath
The path of the folder to clear.

.PARAMETER Age
The age of the files and folders to be removed in days.

.PARAMETER Force
Removes ALL files and folders from the supplied path regardless of age.

.EXAMPLE
Clear-Folder -FilePath "C:\temp" -Age 7
Removes all files and folders from the C:\temp directory that are older than 7 days.

#>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Path", "FilePath")]
        [string]$FolderPath,
        [switch]$Force,
        [int32]$Age = 30
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        if ($PSCmdlet.ShouldProcess($FolderPath, "Remove Folder")) {
            if (Test-Path "$FolderPath") {
                $WinTempList = Get-ChildItem "$FolderPath" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
                foreach ( $Item in $WinTempList) {
                    if ($Force) {
                        Write-Log -Message "Removing all files/folders $($Item.FullName) from $FolderPath" -Component ${CmdletName}
                        Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        if (($Item.CreationTime -lt $(Get-Date).AddDays(-$Age))) {
                            Write-Log -Message "Removing file/folder $($Item.FullName) from $FolderPath older than $age" -Component ${CmdletName}
                            Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }

            } else {
                Write-Log -Message "$FolderPath doesn't exist" -Component ${CmdletName}
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Clear-Folder

#region Connect-Database
Function Connect-Database {
    <#
.SYNOPSIS
    Connects to a LiteDB database.

.DESCRIPTION
    This function connects to a LiteDB database using the specified parameters, such as the database path, read-only mode, shared connection, and optional credentials.

.PARAMETER DatabasePath
    Specifies the path to the LiteDB database file.

.PARAMETER ReadOnly
    Indicates whether to open the database in read-only mode.

.PARAMETER Shared
    Indicates whether to use a shared connection.

.PARAMETER Credentials
    Specifies the credentials for authentication, if required.

.EXAMPLE
    Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly -Shared -Credentials $credentials
    Connects to the LiteDB database located at "C:\Path\To\Database.db" in read-only mode with a shared connection using the specified credentials.

.NOTES
    Author         : Aaron Whittaker
#>
    [CmdletBinding()]
    Param ([Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -IsValid })]
        [string]$DatabasePath,
        [Switch]$ReadOnly,
        [switch]$Shared,
        [string]$Credentials
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Try {
            If ( -Not ([System.Management.Automation.PSTypeName]'LiteDB.LiteDatabase').Type ) {
                if (Test-Path -Path "$Resources\Database\liteDB.dll") {
                    Add-Type -Path "$Resources\Database\liteDB.dll"
                } else {
                    Write-Log -Message "Unable to locate LiteDB dll, unable to continue" -Component ${CmdletName} -Severity 3
                    Exit-Script
                }
            }
            # Test the path and create the path if required
            $Parent = Split-Path -Path $DatabasePath -ErrorAction Stop

            if ((Test-Path -Path $Parent) -eq $false) {
                New-Item -Path $Parent -ItemType Directory -ErrorAction Stop
            }

            $ConnectionParameters = @{
                Filename = $DatabasePath
            }

            # Set read-only mode if specified
            if ($ReadOnly) {
                $ConnectionParameters['ReadOnly'] = $true
            }

            # Set shared connection if specified
            if ($shared) {
                $ConnectionParameters['Connection'] = "shared"
            }

            # Set credentials if provided
            if ($Credentials) {
                $ConnectionParameters['Password'] = $Credentials
            }

            # Try to create or open the LiteDB database
            $database = [LiteDB.LiteDatabase]::new($ConnectionParameters)

            Write-Output -InputObject $database
        } catch {
            # Log an error message if unable to create or open the database
            Write-Log -Message "Unable to create or open the database in $Parent :: $_" -Severity 3 -Component ${CmdletName}
            Throw $_
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Connect-Database

#region Convert-CustomVariableSafeString
Function Convert-CustomVariableSafeString {
    <#
.SYNOPSIS
    Converts the custom variable string into something safe that WorkSpace ONE custom attributes will be able to read
.PARAMETER OriginalString
    The string that you want to convert
.PARAMETER ToSafe
    A switch to tell the function to convert the string to something safe for WS1
.PARAMETER FromSafe
    A switch to tell the function to convert the string from something safe for WS1 into something easier to read e.g. when outputting to a report
.EXAMPLE
    Convert-CustomVariableSafeString -OriginalString $Value -ToSafe
.NOTES

#>
    Param (
        $OriginalString,
        [switch]$ToSafe,
        [switch]$FromSafe
    )

    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

    }
    Process {
        if ($ToSafe) {

            If ($OriginalString -match "^[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-_\+\=\'\,\.]*$") {
                #string is valid
                $ReturnString = $OriginalString
            } else {
                ForEach ($Mapped in $ASCIIStringArray.Values) {
                    $OriginalString = $OriginalString.Replace($Mapped, $ASCIIStringArrayReverse[$Mapped])
                }
                If ($OriginalString -match "[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-_\+\=\'\,\.]*") {
                    $ReturnString = $OriginalString
                } else {
                    $longFormatter = "";
                    foreach ($char in $OriginalString) {
                        if ($char -notmatch "[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-\_\+\=\'\,\.]") {
                            $longFormatter += "`%";
                        } else {
                            $longFormatter += $char;
                        }
                    }
                    $ReturnString = $longFormatter
                }
            }
        }

        if ($FromSafe) {
            $ReturnString = Replace-Ascii -string $OriginalString
        }

        Write-Output -InputObject $ReturnString
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer

    }
}
#endregion Convert-CustomVariableSafeString

#region Convert-RegistryPath
Function Convert-RegistryPath {
    <#
.SYNOPSIS
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
.DESCRIPTION
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
	Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE".
.PARAMETER Key
	Path to the registry key to convert (can be a registry hive or fully qualified path)
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.EXAMPLE
	Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.EXAMPLE
	Convert-RegistryPath -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Key,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string]$SID,
        [Parameter(Mandatory = $false)]
        [switch]$Reverse
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if ($Reverse) {
            ## Convert the registry key hive to the full path, only match if at the beginning of the line
            eIf ($Key -match '^HKEY_LOCAL_MACHINE\|^HKEY_CURRENT_USER\|^HKEY_CLASSES_ROOT\|^HKEY_USERS\|^HKEY_CURRENT_CONFIG\|^HKEY_PERFORMANCE_DATA\') {
                #  Converts registry paths that start with, e.g.: HKLM:
                $key = $key -replace '^HKEY_LOCAL_MACHINE\', 'HKLM:'
                $key = $key -replace '^HKEY_CLASSES_ROOT\', 'HKCR:'
                $key = $key -replace '^HKEY_CURRENT_USER\', 'HKCU:'
                $key = $key -replace '^HKEY_USERS\', 'HKU:'
                $key = $key -replace '^HKEY_CURRENT_CONFIG\', 'HKCC:'
                $key = $key -replace '^HKEY_PERFORMANCE_DATA\', 'HKPD:'
            }
            If ($PSBoundParameters.ContainsKey('SID')) {
                ## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
                If ($key -match '^HKCU:') {
                    $key = $key -replace '^HKCU:', "HKU:\$SID\"
                }
            }

            If ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
                ## Check for expected key string format
                Write-Log -Message "Return fully registry key path [$key]." -Component ${CmdletName}
            } Else {
                #  If key string is not properly formatted, throw an error
                Throw "Unable to detect target registry hive in string [$key]."
            }
        } else {
            ## Convert the registry key hive to the full path, only match if at the beginning of the line
            If ($Key -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') {
                #  Converts registry paths that start with, e.g.: HKLM:\
                $key = $key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
                $key = $key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
                $key = $key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
                $key = $key -replace '^HKU:\\', 'HKEY_USERS\'
                $key = $key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
                $key = $key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
            } ElseIf ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
                #  Converts registry paths that start with, e.g.: HKLM:
                $key = $key -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
                $key = $key -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
                $key = $key -replace '^HKCU:', 'HKEY_CURRENT_USER\'
                $key = $key -replace '^HKU:', 'HKEY_USERS\'
                $key = $key -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
                $key = $key -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
            } ElseIf ($Key -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') {
                #  Converts registry paths that start with, e.g.: HKLM\
                $key = $key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
                $key = $key -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
                $key = $key -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
                $key = $key -replace '^HKU\\', 'HKEY_USERS\'
                $key = $key -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
                $key = $key -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
            }

            If ($PSBoundParameters.ContainsKey('SID')) {
                ## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
                If ($key -match '^HKEY_CURRENT_USER\\') {
                    $key = $key -replace '^HKEY_CURRENT_USER\\', "HKEY_USERS\$SID\"
                }
            }

            ## Append the PowerShell drive to the registry key path
            If ($key -notmatch '^Registry::') {
                [string]$key = "Registry::$key"
            }

            If ($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
                ## Check for expected key string format
                Write-Log -Message "Return fully qualified registry key path [$key]." -Component ${CmdletName}
            } Else {
                #  If key string is not properly formatted, throw an error
                Throw "Unable to detect target registry hive in string [$key]."
            }
        }
        Write-Output -InputObject $key
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Convert-RegistryPath

#region Convert-Size
function Convert-Size {
    <#
.SYNOPSIS
Converts a value from one size unit to another.

.DESCRIPTION
This function converts a value from one size unit (Bytes, KB, MB, GB, or TB) to another specified size unit. It supports conversion between Bytes, Kilobytes (KB), Megabytes (MB), Gigabytes (GB), and Terabytes (TB).

.PARAMETER From
Specifies the input size unit to convert from. Acceptable values are "Bytes", "KB", "MB", "GB", or "TB".

.PARAMETER To
Specifies the output size unit to convert to. Acceptable values are "Bytes", "KB", "MB", "GB", or "TB".

.PARAMETER Value
Specifies the value to be converted.

.PARAMETER Precision
Specifies the number of decimal places in the converted value. Default is 4.

.EXAMPLE
Convert-Size -From KB -To MB -Value 1024
Converts 1024 Kilobytes to Megabytes.

.NOTES
The Convert-Size function provides a convenient way to convert size units in PowerShell scripts, allowing for easy manipulation and presentation of file sizes or other data.
#>
    [cmdletbinding()]
    param(
        [validateset("Bytes", "KB", "MB", "GB", "TB")]
        [string]$From,
        [validateset("Bytes", "KB", "MB", "GB", "TB")]
        [string]$To,
        [Parameter(Mandatory = $true)]
        [double]$Value,
        [int]$Precision = 4
    )
    switch ($From) {
        "Bytes" { $value = $Value }
        "KB" { $value = $Value * 1024 }
        "MB" { $value = $Value * 1024 * 1024 }
        "GB" { $value = $Value * 1024 * 1024 * 1024 }
        "TB" { $value = $Value * 1024 * 1024 * 1024 * 1024 }
    }

    switch ($To) {
        "Bytes" { return $value }
        "KB" { $Value = $Value / 1KB }
        "MB" { $Value = $Value / 1MB }
        "GB" { $Value = $Value / 1GB }
        "TB" { $Value = $Value / 1TB }

    }

    return [Math]::Round($value, $Precision, [MidPointRounding]::AwayFromZero)

}
#endregion Convert-Size

#region Exit-Script
Function Exit-Script {
    <#
.SYNOPSIS
    This function provides an easy way to exit a script with a message and an exit code.
.DESCRIPTION
    The function is meant to be used at the end of a PowerShell script to exit it with an optional exit code and message. These values will be logged, and in case of an error, a restart can also be performed.
.PARAMETER ExitCode
    The integer value that represents the exit code of the script.
.PARAMETER ExitMessage
    The string message that describes why the script is exiting.
.PARAMETER ScriptError
    A switch that indicates if the script is exiting with an error.
.PARAMETER Restart
    A switch that when set to True will cause the computer to be restarted
.EXAMPLE
    Exit-Script -ExitCode 0 -ExitMessage "Script ran successfully."
        In this example, the script will exit with an exit code of 0 and message 'Script ran successfully.'
.NOTES
    This function uses a helper function Write-Log and Write-ScriptHeaderOrFooter to log the message and print header and footer accordingly, it is assumed that these functions are available in the script.
    If "ExitCode" is not provided, the script will exit with a code of 0.
    If "ExitMessage" is not provided, the script will exit with message 'Unknown'
    If the Restart switch is used, it will force the computer to restart.
#>
    Param (
        [Parameter(Mandatory = $false)]
        [int]$ExitCode = 0,
        [string]$ExitMessage,
        [switch]$ScriptError,
        [switch]$Restart
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if ($isTesting -eq $true) {
            Write-Host "The script would exit right now, but this is a test, so its not going to"
        } else {
            if ($ExitCode -and $ExitMessage) {
                $ExitString = "$($ExitMessage): $ExitCode"
            } elseif ($ExitCode.length -gt 0) {
                $ExitString = "$($ExitCode)"
            } elseif ($ExitMessage) {
                $ExitString = "$ExitMessage"
            } else {
                $ExitString = "Unknown"
            }

            if ($ScriptError) {
                Write-Log -Message "Script exiting with an Error: $ExitString" -Component ${CmdletName} -Severity 3
            } else {
                Write-Log -Message "Script exiting: $ExitString" -Component ${CmdletName}
            }

            if ($restart) {
                Restart-Computer -Force
            }
            if ($ExitCode) {
                Write-ScriptHeaderOrFooter -Footer
                Exit $ExitCode
            } else {
                Write-ScriptHeaderOrFooter -Footer
                Exit
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }


}
#endregion Exit-Script

#region Get-ActiveUser
Function Get-ActiveUser {
    <#
.SYNOPSIS
    Gets the active user of the device and returns its session details
.DESCRIPTION

.PARAMETER SearchMode
    "CS" (default): The function uses a C# script file, "GetWin32User.cs", to obtain a list of active users and their domain and session information. If the script file is not found, the function exits without returning any users.
    "Explorer": The function uses the "Explorer" process to obtain a list of active users and their domain and session information.
    "WMI": The function uses the Win32_LoggedOnUser WMI class to obtain a list of active users and their domain and session information. The function excludes certain predefined user account names like "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE" etc.
    "Query": The function uses a query to obtain a list of active users and their domain and session information.

.EXAMPLE
    $ActiveUsers = Get-ActiveUser

    .To get the list of active users using Explorer process
    $ActiveUsers = Get-ActiveUser -SearchMode Explorer

    .To get the list of active users using WMI
    $ActiveUsers = Get-ActiveUser -SearchMode WMI

    .To get the list of active users using Query
    $ActiveUsers = Get-ActiveUser -SearchMode Query
.NOTES
    This function uses a helper function Write-Log and Write-ScriptHeaderOrFooter to log the message and print header and footer accordingly, it is assumed that these functions are available in the script.
#>
    Param (
        [ValidateSet("CS", "Explorer", "WMI", "Query")]
        [string]$SearchMode = "CS"
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $ActiveUsers = @()
        switch ($SearchMode) {
            CS {
                If (Test-Path "$Resources\GetWin32User.cs") {
                    Write-Log -Message "Getting active user via CS script" -Component ${CmdletName} -ScriptSection "Get-ActiveUser"
                    Unblock-File "$Resources\GetWin32User.cs"
                    if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
                        [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
                        Add-Type -Path "$Resources\GetWin32User.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction SilentlyContinue
                    }

                    $tempUsernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:COMPUTERNAME")

                    foreach ($User in $tempUsernameLookup) {
                        $UPN = ([ADSI]"LDAP://<SID=$($user.SID)>").UserPrincipalName
                        $usernameProp = @{"Username" = $User.UserName; "Domain" = $User.DomainName; "IsConsoleSession" = $User.IsConsoleSession; "IsCurrentSession" = $User.IsCurrentSession; "SID" = $user.SID; "UPN" = "$UPN" }
                        $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
                        $ActiveUsers += $usernameLookup
                    }

                }
            }
            Explorer {
                Write-Log -Message "Getting all active users via Explorer process." -Component ${CmdletName} -ScriptSection "Get-ActiveUser"
                $ExplorerProcess = (Get-Process -Name "Explorer" -IncludeUserName).Username | Select-Object -Unique

                foreach ($Process in $ExplorerProcess) {
                    $User = New-Object System.Security.Principal.NTAccount($Process)
                    Try {
                        $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
                    } Catch {
                        $sid = $_.Exception.Message;
                    }
                    $UPN = ([ADSI]"LDAP://<SID=$($SID)>").UserPrincipalName
                    $usernameProp = @{"Username" = $ExplorerProcess.Split("\")[1]; "Domain" = $ExplorerProcess.Split("\")[0]; "IsConsoleSession" = ""; "IsCurrentSession" = ""; "SID" = "$sid"; "UPN" = "$UPN" }
                    $ActiveUsers += New-Object -TypeName PSCustomObject -Property $usernameProp;
                }

            }
            WMI {
                $ExcludedActiveUsers = @("SYSTEM",
                    "LOCAL SERVICE",
                    "NETWORK SERVICE",
                    "DWM-*",
                    "UMFD-*",
                    "ANONYMOUS LOGON")

                Write-Log -Message "Getting all active users via Win32_LoggedOnUser." -Component ${CmdletName} -ScriptSection "Get-ActiveUser"

                $AllActiveUsers = Get-CimInstance Win32_LoggedOnUser | Where-Object { ($_.antecedent.domain -ne $ENV:ComputerName) }

                $ExcludedUsers = @()
                foreach ($ActiveUser in $AllActiveUsers.Name) {
                    foreach ($ExcludeUser in $ExcludedActiveUsers) {
                        if ($ActiveUser -like $ExcludeUser) {
                            $tempUser = [PSCustomObject]@{
                                User   = $ActiveUser
                                Status = "Exclude"
                            }
                            $ExcludedUsers += $tempUser
                        }
                    }

                }

                foreach ($user in ($AllActiveUsers.Antecedent | Where-Object { $_.Name -notin $ExcludedUsers.User })) {
                    $UserSID = New-Object System.Security.Principal.NTAccount($user.Name)
                    Try {
                        $sid = $UserSID.Translate([System.Security.Principal.SecurityIdentifier]).value;
                    } Catch {
                        $sid = $_.Exception.Message;
                    }
                    $UPN = ([ADSI]"LDAP://<SID=$($SID)>").UserPrincipalName
                    $usernameProp = @{"Username" = $user.Name; "Domain" = $user.Domain; "IsConsoleSession" = ""; "IsCurrentSession" = ""; "SID" = $SID; "UPN" = "$UPN" }
                    $ActiveUsers += New-Object -TypeName PSCustomObject -Property $usernameProp;
                }

            }
            query {
                $report = @()
                $sessions = query session
                1..($sessions.count - 1) | ForEach-Object {
                    $temp = "" | Select-Object Computer, SessionName, Username, Id, State, Type, Device
                    $temp.Computer = $ENV:Computername
                    $temp.SessionName = $sessions[$_].Substring(1, 18).Trim()
                    $temp.Username = $sessions[$_].Substring(19, 20).Trim()
                    $temp.Id = $sessions[$_].Substring(39, 9).Trim()
                    $temp.State = $sessions[$_].Substring(48, 8).Trim()
                    $temp.Type = $sessions[$_].Substring(56, 12).Trim()
                    $temp.Device = $sessions[$_].Substring(68).Trim()
                    $report += $temp
                }

                $report | Where-Object { $_.State -eq "Active" } | ForEach-Object {
                    $UserSID = New-Object System.Security.Principal.NTAccount($_.username)
                    Try {
                        $sid = $UserSID.Translate([System.Security.Principal.SecurityIdentifier]).value;
                    } Catch {
                        $sid = $_.Exception.Message;
                    }
                    $UPN = ([ADSI]"LDAP://<SID=$($SID)>").UserPrincipalName
                    $usernameProp = @{"Username" = $_.Username; "Domain" = ""; "IsConsoleSession" = if ($_.SessionName -like "console") { "True" }Else { "False" }; "IsCurrentSession" = "True"; "SID" = $sid; "UPN" = "$UPN" }
                    $ActiveUsers += New-Object -TypeName PSCustomObject -Property $usernameProp;
                }

            }
            Default {}
        }

        Write-Output -InputObject $ActiveUsers
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-ActiveUser

#region Get-ADSite
Function Get-ADSite {
    <#
.SYNOPSIS
    Attempts to get the current AD site first using .Net, if that doesn't work it will attempt to retrieve it using 'nltest'.
    If it is still unable to retrieve the ADsite using either of those methods it will return 'error' as the AD site.

.EXAMPLE
    $ADSite = Get-ADSite
.NOTES
    'The long way' method using DHCP lookups was taking too long and was unreliable to function in agency so was removed for efficiency.
#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        try {
            Write-Log -Message "Attempting to get AD site using .Net" -Component ${CmdletName}
            [string]$ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
        } catch {
            try {
                Write-Log -Message "Unable to get AD site using .Net. Trying with 'nltest'" -Severity 2 -Component ${CmdletName}
                [string]$ADSite = (nltest /server:$ENV:COMPUTERNAME /dsgetsite)[0]
            } catch {
                Write-Log -Message "Unable to get AD site using any method. Writing to registry" -Severity 3 -Component ${CmdletName}
                $ADSite = "Error"
            }
        }

        Write-Log -Message "AD Site located: $ADSite" -Component ${CmdletName}
        Write-Output -InputObject $ADSite
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-ADSite

#region Get-DatabaseEntry
Function Get-DatabaseEntry {
    <#
.SYNOPSIS
    Retrieves data from a LiteDB database.

.DESCRIPTION
    This function retrieves data from a specified collection in a LiteDB database.
    You can use optional parameters to filter, project, and sort the results.

.PARAMETER Database
    Specifies the LiteDB database object.

.PARAMETER CollectionName
    Specifies the name of the collection from which to retrieve data.

.PARAMETER Filter
    Specifies optional filter parameters to narrow down the results.

.PARAMETER Sort
    Specifies optional sort parameters to order the results.

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    Get-DatabaseEntry -Database $database -CollectionName "Users"

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $filter = @{ "City" = "New York" }
    Get-DatabaseEntry -Database $database -CollectionName "Users" -Filter $filter

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $sort = @{ "Age" = 1 }
    Get-DatabaseEntry -Database $database -CollectionName "Users" -Sort $sort

.NOTES

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,
        [Parameter(Mandatory = $true)]
        [string]$CollectionName,
        [HashTable]$Filter = @{},
        [switch]$All,
        [switch]$Last,
        [ValidateSet("Ascending", "Descending")]
        [string]$Sort = "Ascending"

    )

    Begin {
        # Get the current cmdlet name
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        # Write function header
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }

    Process {
        try {
            # Get the collection
            $collection = $Database.GetCollection($CollectionName)
            $tempresults = [ordered]@{}
            # Build LiteDB Query
            if ($All.IsPresent) {
                $query = $collection.FindAll()
                # Execute the query and convert results to PSCustomObject
                $tempresults = $query | ForEach-Object {
                    Convert-BsonDocumentToPSCustomObject $_
                }
            } else {
                $query = $collection.Query()

                # Add filter criteria to the query
                foreach ($key in $Filter.Keys) {
                    $query = $query.Where([LiteDB.Query]::EQ($key, $Filter[$key]))
                }

                # Execute the query and convert results to PSCustomObject
                $tempresults = $query.ToDocuments() | ForEach-Object {
                    Convert-BsonDocumentToPSCustomObject $_
                }
            }

            if ($Last.IsPresent) {
                $ReturnObject = $tempresults | Select-Object -Last 1
            } elseif ($null -eq $tempresults) {
                $ReturnObject = $tempresults
            } else {
                $ReturnObject = $tempresults
            }

            # Output the query results
            Write-Output $ReturnObject
        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to retrieve data from the LiteDB database. $_" -Severity 3 -Component ${CmdletName}
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DatabaseEntry

#region Convert-BsonDocumentToPSCustomObject
Function Convert-BsonDocumentToPSCustomObject {
    <#
.SYNOPSIS
Converts a LiteDB BsonDocument to a PowerShell custom object.

.DESCRIPTION
This function converts a LiteDB BsonDocument to a PowerShell custom object. It iterates through the properties of the BsonDocument, extracts the keys and values, and creates a hashtable. Finally, it converts the hashtable to a PSCustomObject and outputs it.

.EXAMPLE
Convert-BsonDocumentToPSCustomObject -BsonDocument $BsonDoc
Converts a LiteDB BsonDocument named $BsonDoc to a PowerShell custom object.

.NOTES
The Convert-BsonDocumentToPSCustomObject function provides a convenient way to convert LiteDB BsonDocument objects to PSCustomObject, making it easier to work with data retrieved from LiteDB databases in PowerShell scripts.
#>
    Param ([LiteDB.BsonDocument]$BsonDocument)

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $hashtable = @{}
        foreach ($property in $BsonDocument.RawValue.GetEnumerator()) {
            $key = $property.Key
            $value = if ($property.Value -is [LiteDB.BsonValue]) {
                $property.Value.RawValue
            } else {
                $property.Value
            }
            $hashtable[$key] = $value
        }
        Write-Output -InputObject $hashtable
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Convert-BsonDocumentToPSCustomObject

#region Convert-Database
Function Convert-Database {
    <#
.SYNOPSIS
    Converts the information currently stored in the registry database to the new liteDB database. Should only be needed to run once
.DESCRIPTION

.EXAMPLE
    Convert-Database -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Convert-Database

#region Update-DatabaseEntry
Function Update-DatabaseEntry {
    <#
.SYNOPSIS
    Updates an entry in a LiteDB database collection based on the provided filter criteria.

.DESCRIPTION
    This function updates an entry in a LiteDB database collection based on the provided filter criteria.
    It takes the LiteDB database object, collection name, filter criteria, and update data as parameters.
    The function retrieves the entry matching the filter criteria, updates its fields with the provided data,
    and then updates the entry in the collection.

.PARAMETER Database
    The LiteDB database object to perform the update operation on.

.PARAMETER CollectionName
    The name of the collection in the LiteDB database where the entry will be updated.

.PARAMETER Filter
    A hashtable representing the filter criteria to identify the entry to be updated.

.PARAMETER UpdateData
    A hashtable containing the data to update the matching entry with.

.NOTES
    Author:         [Author Name]
    Creation Date:  [Creation Date]

.EXAMPLE
    $database = New-LiteDBDatabase -DatabasePath "C:\data.db"
    $filter = @{ Name = "John" }
    $updateData = @{ Age = 30; City = "New York" }
    Update-DatabaseEntry -Database $database -CollectionName "Users" -Filter $filter -UpdateData $updateData
    This example updates an entry in the "Users" collection of the LiteDB database located at "C:\data.db"
    where the name is "John". It updates the age to 30 and the city to "New York".

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,
        [Parameter(Mandatory = $true)]
        [string]$CollectionName,
        [Parameter(Mandatory = $true)]
        [HashTable]$Filter,
        [Alias("Data")]
        [Parameter(Mandatory = $true)]
        [HashTable]$UpdateData
    )

    Begin {
        # Get the current cmdlet name
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        # Write function header
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }

    Process {
        try {
            # Get the collection
            $collection = $Database.GetCollection($CollectionName)

            $Item = Get-DatabaseEntry -Database $Database -CollectionName $CollectionName -Filter $Filter

            if ($Item._id.Count -gt 1) {
                Write-Log -Message "Multiple records have been found with the criteria, please select a better filter" -Component ${CmdletName}
                throw
            }

            $Result = $Collection.FindById($Item._id)
            # Convert update data hashtable to BsonDocument
            foreach ($key in $UpdateData.Keys) {
                $Result[$key] = $UpdateData[$key]
            }

            # Execute the update
            $collection.Update($Result)

            # Output the update result
            #Write-Output -InputObject $updateResult

        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to update entry in the LiteDB database. $_" -Severity 3 -Component ${CmdletName}
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-DatabaseEntry

#region Remove-DatabaseEntry
Function Remove-DatabaseEntry {
    <#
.SYNOPSIS
    Deletes an entry from a LiteDB database collection based on specified filter criteria.

.DESCRIPTION
    This function removes an entry from a LiteDB database collection based on the provided filter criteria.
    It performs a check to ensure that only one entry matches the filter to prevent accidental deletion of multiple entries.

.PARAMETER Database
    The LiteDB database to operate on.

.PARAMETER CollectionName
    The name of the collection from which to remove the entry.

.PARAMETER Filter
    The filter criteria to identify the entry to be deleted. Should be a hashtable of field-value pairs.

.EXAMPLE
    $filter = @{ "Name" = "John" }
    Remove-DatabaseEntry -Database $SystemDatabase -CollectionName "Users" -Filter $filter

.NOTES

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,

        [Parameter(Mandatory = $true)]
        [string]$CollectionName,

        [Parameter(Mandatory = $true)]
        [HashTable]$Filter
    )

    Begin {
        # Get the current cmdlet name
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        # Write function header
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }

    Process {
        try {
            # Get the collection
            $collection = $Database.GetCollection($CollectionName)

            $Item = Get-DatabaseEntry -Filter $Filter -Database $Database -CollectionName $CollectionName -Last

            # Check if multiple entries were found
            if ($Item.Count -gt 1) {
                throw "Multiple entries found for the specified filter. Please provide a more specific filter to avoid accidental deletion."
            }

            # Check if any entry was found
            if ($Item.Count -eq 0) {
                Write-Output "No entry found for the specified filter in collection '$CollectionName'. Nothing deleted."
                return
            }

            # Execute the delete
            $deleteResult = $collection.Delete($Item._id)

            if ($deleteResult -eq $true) {
                Write-Output "Deleted $($Filter.Values) entry from collection '$CollectionName'."
            } else {
                Write-Output "Failed to delete $($Filter.Values) entry from collection '$CollectionName'."
            }

        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to delete entry from the LiteDB database. $_" -Severity 3 -Component ${CmdletName}
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Remove-DatabaseEntry

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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
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
        Write-Log -Message "Returning :: $ReturnObject" -DebugMessage -Component ${CmdletName}
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DiskSpace

#region Get-EnrollmentIDs
Function Get-EnrollmentIDs {
    <#
.SYNOPSIS
Retrieves enrollment IDs and associated user information from the registry.

.DESCRIPTION
This function retrieves enrollment IDs and associated user information from the registry. It is particularly useful in environments where devices are enrolled in management systems such as AirwatchMDM. The function scans the registry for enrollment keys and extracts user information associated with the specified provider ID.

.EXAMPLE
Get-EnrollmentIDs -Return

Retrieves enrollment IDs and associated user information from the registry and returns the results as a custom object.

.NOTES
The Get-EnrollmentIDs function is designed to facilitate the retrieval of enrollment IDs and user information stored in the registry. It extracts relevant data based on specified provider IDs, such as AirwatchMDM, and allows for seamless integration with management systems. The function provides a convenient way to access enrollment details programmatically, aiding in device management and administration tasks.
#>
    Param ([switch]$Return
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        # Get enrollment and enrolled user
        $Path = $($Global:VariableTable.RegKeyPaths.EnrollmentPath).Replace("\##EnrollmentID##", "")
        $EnrollmentKeys = Get-ChildItem -Path "$Path"

        foreach ($Key in $EnrollmentKeys) {
            if ($Key.Property -eq "ProviderID") {
                $KeyPath = Convert-RegistryPath -Key $Key.Name
                $ProviderID = Get-ItemProperty -Path "$KeyPath" -Name "ProviderID"
                if ($ProviderID.ProviderID -eq "AirwatchMDM") {
                    $TempRegInfo = Get-ItemProperty -Path "$KeyPath"
                    $Global:VariableTable.EnrollmentUser.UserUPN = $TempRegInfo.UPN
                    $Global:VariableTable.EnrollmentUser.UserName = (Get-UserName -SID $TempRegInfo.SID).Username
                    $Global:VariableTable.EnrollmentUser.SID = $TempRegInfo.SID
                }
            }
        }

        if ($Return.IsPresent) {
            $ReturnObject = [PSCustomObject]@{
                UserUPN  = $Global:VariableTable.EnrollmentUser.UserUPN
                UserName = $Global:VariableTable.EnrollmentUser.UserName
                SID      = $Global:VariableTable.EnrollmentUser.SID
            }
            Write-Output -InputObject $ReturnObject
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-EnrollmentIDs

#region Get-ErrorCode
Function Get-ErrorCode {
    <#
.SYNOPSIS
Retrieves error codes and reasons based on specified error descriptions.

.DESCRIPTION
This function returns error codes and reasons corresponding to given error descriptions. It is useful for mapping descriptive error messages to standardized error codes for better handling and logging of errors.

.EXAMPLE
Get-ErrorCode -Reason "Unable to retrieve device information"

Retrieves the error code and reason for the specified error description "Unable to retrieve device information".

.NOTES
The Get-ErrorCode function provides a convenient way to obtain error codes and reasons based on descriptive error messages. It allows for standardizing error handling by mapping human-readable error descriptions to predefined error codes, facilitating consistent error reporting and troubleshooting.
#>
    Param ([string]$Reason
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        switch ($Reason) {
            "Unable to retrieve device information" {
                $ReturnObject = @{
                    "Code"   = 70001
                    "Reason" = "Unable to retrieve device information"
                }
            }
            "Unknown Agency" {
                $ReturnObject = @{
                    "Code"   = 70002
                    "Reason" = "Unable to retrieve device information"
                }
            }
            "Unable to create registry key" {
                $ReturnObject = @{
                    "Code"   = 70003
                    "Reason" = "Unable to create registry key"
                }
            }
            "Unable to read registry variables" {
                $ReturnObject = @{
                    "Code"   = 70004
                    "Reason" = "Unable to read registry variables"
                }
            }
            "Completed first run" {
                $ReturnObject = @{
                    "Code"   = 0
                    "Reason" = "Completed first run"
                }
            }
            "API: Unable to confirm if killswitch has been engaged" {
                $ReturnObject = @{
                    "Code"   = 70005
                    "Reason" = "API: Unable to confirm if killswitch has been engaged"
                }
            }
            Default {
                $ReturnObject = @{
                    "Code"   = 99999
                    "Reason" = "Unknown error"
                }
            }
        }
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-ErrorCode

#region Get-FolderList
Function Get-FolderList {
    <#
.SYNOPSIS
Retrieves a list of folders based on specified criteria.

.DESCRIPTION
This function retrieves a list of folders based on specified parameters such as folder names, base paths, omitted folders, and file extensions. It allows for flexible querying of folder structures to find specific folders matching given criteria.

.EXAMPLE
Get-FolderList -FolderName "Documents" -BasePath "C:\Users" -OmitFolders "C:\Users\John\Downloads" -FindExtension ".txt"

Retrieves folders named "Documents" within the "C:\Users" directory, excluding the "C:\Users\John\Downloads" folder, and filters for files with a ".txt" extension within those folders.

.NOTES
The Get-FolderList function provides a versatile way to search for folders within a directory hierarchy while allowing customization through various parameters. It enables efficient querying of folder structures to locate specific folders based on user-defined criteria.
#>
    [cmdletbinding()]
    Param (
        [string[]]
        $FolderName,
        [Parameter()]
        [Alias("FolderPath")]
        [string[]]
        $BasePath,

        [Parameter()]
        [string[]]
        $OmitFolders,

        [Parameter()]
        [string[]]
        $FindExtension
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        #All folders and look for files with a particular extension
        if ($FolderName -eq 'all' -and $FindExtension) {
            $allFolders = Get-ChildItem -LiteralPath $BasePath -Force -Recurse | Where-Object { ($OmitFolders -notcontains $_.FullName) -and ($FindExtension -contains $_.Extension) }
            #All folders
        } elseif ($FolderName -eq 'all') {
            $allFolders = Get-ChildItem -LiteralPath $BasePath -Force | Where-Object { $OmitFolders -notcontains $_.FullName }
            #Specified folder names and look for files with a particular extension
        } elseif ($FolderName -ne 'all' -and $FindExtension) {
            $allFolders = Get-ChildItem -LiteralPath $BasePath -Force -Recurse | Where-Object { ($_.FullName -match ".+$FolderName.+") -and ($OmitFolders -notcontains $_.FullName) -and ($FindExtension -contains $_.Extension) }
        } else {
            $allFolders = Get-ChildItem -LiteralPath $BasePath -Force | Where-Object { ($_.BaseName -match "$FolderName") -and ($OmitFolders -notcontains $_.FullName) }
        }

        #Test for null, return just folder if no subfolders
        $splitPath = Split-Path -Path $BasePath
        if (!($allFolders) -and (Test-Path -Path $splitPath -ErrorAction SilentlyContinue)) {
            $findName = Split-Path $BasePath -Leaf
            $allFolders = Get-ChildItem -LiteralPath $splitPath | Where-Object { $_.Name -eq $findName }
        }

        Write-Output -InputObject $allFolders

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-FolderList

#region Get-FolderSize
function Get-FolderSize {
    <#
    .SYNOPSIS
    Get-FolderSize
    Returns the size of folders in MB and GB.
    You can change the base path, omit folders, as well as output results in various formats.
    .DESCRIPTION
    This function will get the folder size in MB and GB of folders found in the basePath parameter.
    The BasePath parameter defaults to the current directory.
    .PARAMETER BasePath
    This parameter allows you to specify the base path you'd like to get the child folders of.
    It defaults to where the module was run from via (Get-Location).
    .PARAMETER FolderName
    This parameter allows you to specify the name of a specific folder you'd like to get the size of.
    .PARAMETER AddTotal
    This parameter adds a total count at the end of the array
    .PARAMETER OmitFolders
    This parameter allows you to omit folder(s) (array of string) from being included
    .PARAMETER Output
    Use this option to output the results. Valid options are csv, xml, or json
    .PARAMETER OutputPath
    Specify the path you want to use when outputting the results as a csv, xml, or json file
    Do not include a trailing slash
    Example: C:\users\you\Desktop
    Defaults to (Get-Location)
    This will be where you called the module from
    .PARAMETER OutputFile
    This allows you to specify the path and file name you'd like for output

    Example: C:\users\you\desktop\output.csv
    .PARAMETER OutputSort
    This allows you to specify what you'd like to sort by for the csv/json/xml output.
    Valid options are FolderSize and SizeBytes
    .PARAMETER AddFileTotals
    This parameter allows you to add file totals to the results
    Note: This will reduce performance of the script by around 30%!
    .EXAMPLE
    Get-FolderSize | Format-Table -AutoSize
    FolderNameSizeBytes SizeMB     SizeGB

    $GetCurrent    193768 0.18 MB      0.00 GB
    $RECYCLE.BIN 20649823 19.69 MB     0.02 GB
    $SysReset    53267392 50.80 MB     0.05 GB
    Config.Msi    0.00 MB      0.00 GB
    Documents and Settings0.00 MB      0.00 GB
    Games     48522184491 46,274.36 MB 45.19 GB
    .EXAMPLE
    Get-FolderSize -BasePath 'C:\Program Files'

    FolderName   SizeBytes SizeMB    SizeGB
    7-Zip    4588532 4.38 MB     0.00 GB
    Adobe 3567833029 3,402.55 MB 3.32 GB
    Application Verifier      353569 0.34 MB     0.00 GB
    Bonjour   615066 0.59 MB     0.00 GB
    Common Files   489183608 466.52 MB   0.46 GB
    .EXAMPLE
    Get-FolderSize -BasePath 'C:\Program Files' -FolderName IIS
    FolderName SizeBytes SizeMB SizeGB

    IIS    5480411 5.23 MB  0.01 GB
    .EXAMPLE
    $getFolderSize = Get-FolderSize
    $getFolderSize | Format-Table -AutoSize
    FolderName SizeGB SizeMB

    Public     0.00 GB  0.00 MB
    thegn      2.39 GB  2,442.99 MB
    .EXAMPLE
    $getFolderSize = Get-FolderSize -Output csv -OutputPath ~\Desktop
    $getFolderSize

    FolderName SizeGB SizeMB

    Public     0.00 GB  0.00 MB
    thegn      2.39 GB  2,442.99 MB
    (Results will also be exported as a CSV to your Desktop folder)
    .EXAMPLE
    Sort by size descending
    $getFolderSize = Get-FolderSize | Sort-Object SizeBytes -Descending
    $getFolderSize
    FolderNameSizeBytes SizeMB     SizeGB
    Users     76280394429 72,746.65 MB 71.04 GB
    Games     48522184491 46,274.36 MB 45.19 GB
    Program Files (x86)       27752593691 26,466.94 MB 25.85 GB
    Windows   25351747445 24,177.31 MB 23.61 GB
    .EXAMPLE
    Omit folder(s) from being included
    Get-FolderSize.ps1 -OmitFolders 'C:\Temp','C:\Windows'
    .EXAMPLE
    Add file counts for each folder
    Note: This will slow down the execution of the script by around 30%

    $results = Get-FolderSize -AddFileTotal
    PS /Users/ninja/Documents/repos/PSFolderSize> $results[0] | Format-List *
    FolderName  : .git
    SizeBytes   : 228591
    SizeMB      : 0.22
    SizeGB      : 0.00
    FullPath    : /Users/ninja/Documents/repos/PSFolderSize/.git
    HostName    : njambp.local
    FileCount   : 382
    #>
    [cmdletbinding(
        DefaultParameterSetName = 'default'
    )]
    param(
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'default')]
        [Alias('Path')]
        [String[]]$BasePath = (Get-Location),
        [Parameter(Mandatory = $false, ParameterSetName = 'default')]
        [Alias('Name')]
        [String[]]$FolderName = 'all',
        [Parameter(
            ParameterSetName = 'default'
        )]
        [String[]]$OmitFolders,
        [Parameter(
            ParameterSetName = 'default'
        )]
        [Switch]$AddTotal,
        [Parameter(ParameterSetName = 'default')]
        [Switch]$AddFileTotals,

        [Parameter(
            ParameterSetName = 'default'
        )]
        [Switch]
        $UseRobo,

        [Parameter(
            ParameterSetName = 'default'
        )]
        [Parameter(
            ParameterSetName = 'outputWithType'
        )]
        [ValidateSet('csv', 'xml', 'json')]
        [String]
        $Output,

        [Parameter(
            ParameterSetName = 'default'
        )]
        [Parameter(
            ParameterSetName = 'outputWithType'
        )]
        [String]
        $OutputPath = (Get-Location),

        [Parameter(
            ParameterSetName = 'default'
        )]
        [Parameter(
            ParameterSetName = 'outputWithType'
        )]
        [ValidateSet('FolderName', 'SizeBytes')]
        [String]
        $OutputSort,

        [Parameter(
            ParameterSetName = 'default'
        )]
        [String]
        $OutputFile = [string]::Empty
    )

    begin {
        #Get a list of all the directories in the base path we're looking for.
        $allFolders = Get-FolderList -FolderName $FolderName -OmitFolders $OmitFolders -BasePath $BasePath

        #Create list to store folder objects found with size info.
        [System.Collections.Generic.List[Object]]$folderList = @()

        #Get hostname
        $hostName = [System.Net.Dns]::GetHostByName((hostname)).HostName
    }
    process {
        #Go through each folder in the base path.
        $allFolders | ForEach-Object {

            #Clear out the variables used in the loop.
            $folder = $null
            $fullPath = $null
            $folderInfo = $null
            $folderObject = $null
            $folderSize = $null
            $folderSizeInBytes = $null
            $folderSizeInMB = $null
            $folderSizeInGB = $null
            $folderBaseName = $null
            $totalFiles = $null

            $folder = $_

            #Store the full path to the folder and its name in separate variables
            $fullPath = $folder.FullName
            $folderBaseName = $folder.BaseName

            Write-Verbose "Working with [$fullPath]..."

            #Get folder info / sizes
            if ($UseRobo) {
                $folderSize = Get-RoboSize -Path $fullPath -DecimalPrecision 2

                $folderSizeInBytes = $folderSize.TotalBytes
                $folderSizeInKB = [math]::Round($folderSize.TotalKB, 2)
                $folderSizeInMB = [math]::Round($folderSize.TotalMB, 2)
                $folderSizeInGB = [math]::Round($folderSize.TotalGB, 2)
            } else {
                $folderInfo = Get-ChildItem -LiteralPath $fullPath -Recurse -Force -ErrorAction SilentlyContinue
                $folderSize = $folderInfo | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue

                #We use the string format operator here to show only 2 decimals, and do some PS Math.
                if ($folderSize.Sum) {
                    $folderSizeInBytes = $folderSize.Sum
                    $folderSizeInKB = [math]::Round($folderSize.Sum / 1KB, 2)
                    $folderSizeInMB = [math]::Round($folderSize.Sum / 1MB, 2)
                    $folderSizeInGB = [math]::Round($folderSize.Sum / 1GB, 2)
                }
            }

            #Here we create a custom object that we'll add to the list
            $folderObject = [PSCustomObject]@{
                PSTypeName = 'PS.Folder.List.Result'
                FolderName = $folderBaseName
                SizeBytes  = $folderSizeInBytes
                SizeKB     = $folderSizeInKB
                SizeMB     = $folderSizeInMB
                SizeGB     = $folderSizeInGB
                FullPath   = $fullPath
                HostName   = $hostName
            }

            #Add file totals if switch is true
            if ($AddFileTotals) {
                $totalFiles = ($folderInfo | Where-Object { !$_.PSIsContainer }).Count
                $folderObject | Add-Member -MemberType NoteProperty -Name FileCount -Value $totalFiles
            }
            #Add the object to the list
            $folderList.Add($folderObject)
        }

        if ($AddTotal) {

            $grandTotal = $null
            $grandTotalFiles = $null

            if ($folderList.Count -gt 1) {
                $folderList | ForEach-Object {
                    if ($_.SizeBytes -gt 0) {
                        $grandTotal += $_.SizeBytes
                    }
                }
                $totalFolderSizeInKB = [math]::Round($grandTotal / 1KB, 2)
                $totalFolderSizeInMB = [math]::Round($grandTotal / 1MB, 2)
                $totalFolderSizeInGB = [math]::Round($grandTotal / 1GB, 2)
                $folderObject = [PSCustomObject]@{
                    PSTypeName = 'PS.Folder.List.Result'
                    FolderName = "GrandTotal for [$BasePath]"
                    SizeBytes  = $grandTotal
                    SizeKB     = $totalFolderSizeInKB
                    SizeMB     = $totalFolderSizeInMB
                    SizeGB     = $totalFolderSizeInGB
                    FullPath   = 'N/A'
                    HostName   = $hostName
                }
            }
            if ($AddFileTotals) {
                $folderList | ForEach-Object {
                    $grandTotalFiles += $_.FileCount
                }
                $folderObject | Add-Member -MemberType NoteProperty -Name FileCount -Value $grandTotalFiles
            }
            #Add the object to the list
            $folderList.Add($folderObject)
        }
    }
    end {
        if ($Output -or $OutputFile) {
            if (!$OutputFile) {
                $fileName = "{2}\{0:MMddyy_HHmm}.{1}" -f (Get-Date), $Output, $OutputPath
            } else {
                $fileName = $OutputFile
                $Output = $fileName.Substring($fileName.LastIndexOf('.') + 1)
            }
            Write-Verbose "Attempting to export results to -> [$fileName]!"
            try {
                switch ($Output) {
                    'csv' {
                        $folderList | Sort-Object $OutputSort -Descending | Export-Csv -Path $fileName -NoTypeInformation -Force
                    }
                    'xml' {
                        $folderList | Sort-Object $OutputSort -Descending | Export-Clixml -Path $fileName
                    }
                    'json' {
                        $folderList | Sort-Object $OutputSort -Descending | ConvertTo-Json | Out-File -FilePath $fileName -Force
                    }
                }
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Error "Error exporting file to [$fileName] -> [$errorMessage]!"
            }
        }
        #Return the object array with the objects selected in the order specified
        Return $folderList | Sort-Object SizeBytes -Descending
    }
}
#endregion Get-FolderSize

#region Format-Date
Function Format-Date {
    <#
.SYNOPSIS
Formats a date object into a specified date format.

.DESCRIPTION
This function takes a date object as input and formats it according to a specified date format. The formatted date string is then returned as output.

.EXAMPLE
Format-Date -Date (Get-Date) -DateFormat "yyyy-MM-dd HH:mm:ss"

Formats the current date and time into the format "yyyy-MM-dd HH:mm:ss".

.NOTES
The Format-Date function is useful for converting date objects into custom date formats within PowerShell scripts or functions. It provides flexibility in displaying dates according to specific requirements.

#>
    Param ($Date, $DateFormat
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $ReturnObject = "{0:$DateFormat}" -f $Date
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Format-Date

#region Format-ProfileData
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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
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
        }

        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Format-ProfileData

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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Write-Log -Message "Getting all Logon events. This could take a while." -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

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
                #TimeCreated = Format-Date -Date $EventXML.Event.System.TimeCreated.SystemTime -DateFormat $DateFormat
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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-LogonEvents

#region Get-LocalUserProfiles
Function Get-LocalUserProfiles {
    <#
.SYNOPSIS
Retrieves information about local user profiles, including profile sizes, logon events, and last modified time.
.DESCRIPTION
The Get-LocalUserProfiles function collects data about local user profiles on a system. It retrieves information such as profile sizes, logon events, last modified time of the NTUser.dat file, and more. The function uses various methods, including querying CIM instances, reading registry entries, analyzing file system data, and examining event logs to gather the required information.
.EXAMPLE
    $UserProfiles = Get-LocalUserProfiles
.NOTES

#>
    Param ()

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $ProfileRegistryList = $Global:VariableTable.RegKeyPaths.ProfileList
        $ExcludedActiveUsers = $Global:VariableTable.Users.ExcludedActiveUsers
        $ExcludedLocalSIDs = $Global:VariableTable.Users.ExcludedLocalSIDs
        $ExcludedUserNames = $Global:VariableTable.Users.ExcludedUserNames
        $ExcludedDomains = $Global:VariableTable.Users.ExcludedDomains

        Write-Log -Message "Getting all profiles." -Component ${CmdletName} -ScriptSection "Get-Profiles"

        $AllUserProfilesCIM = Get-CimInstance -ClassName Win32_UserProfile -Filter "Special='False'"

        $AllUserProfilesRegistry = Get-ChildItem -Path "$($ProfileRegistryList.Replace("HKEY_LOCAL_MACHINE","HKLM:"))" | ForEach-Object { Get-ItemProperty $_.PSPath }
        Write-Log -Message "Getting all profile sizes, this could take a while" -Component ${CmdletName} -ScriptSection "Get-ProfileSizes"

        $BasePath = "$ENV:SystemDrive\Users"
        $OmitFolders = @("$BasePath\Public", "$BasePath\desktop.ini", "$BasePath\Default User", "$BasePath\Default", "$BasePath\All Users")

        $AllUserProfilesFileSystem = Get-FolderSize -BasePath $BasePath -OmitFolders $OmitFolders

        $TempAllActiveUsers = (Get-CimInstance Win32_LoggedOnUser).antecedent
        $AllActiveUsers = @()

        foreach ($ActiveUsers in $TempAllActiveUsers) {
            $TempRemoveAccount = $false
            foreach ($ExcludedActiveNames in $ExcludedActiveUsers) {
                if ($ActiveUsers.Name -like "*$ExcludedActiveNames*") {
                    $TempRemoveAccount = $True
                }
            }

            foreach ($ExcludedNames in $ExcludedUserNames) {
                if ($ActiveUsers.Name -like "*$ExcludedNames*") {
                    $TempRemoveAccount = $True
                }
            }

            if ($ActiveUsers.Domain -in $ExcludedDomains) {
                $TempRemoveAccount = $True
            }

            if ($TempRemoveAccount -eq $False) {
                $temp = [PSCustomObject]@{
                    Username = $($ActiveUsers.Name)
                    Domain   = $($ActiveUsers.Domain)
                }
                if ($AllActiveUsers.Username -notcontains $($ActiveUsers.Name)) {
                    $AllActiveUsers += $temp
                }
            }

        }

        $AllLogonEvents = Get-LogonEvents

        Write-Log -Message "Getting database records" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

        $DatabaseProfiles = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Users"

        # Go through each profile, CIM, Reg, File, Event Log and add to table
        Write-Log -Message "Passing through each profile" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

        $ProfileList = @()

        foreach ($CIMProfile in $AllUserProfilesCIM) {
            $CIMLastUseTime = Format-Date -Date $CIMProfile.LastUseTime
            $ProfileData = Format-ProfileData -SID $CIMProfile.SID -Path $CIMProfile.LocalPath -CIMLastUseTime $CIMLastUseTime

            $ProfileList += $ProfileData
        }

        foreach ($RegistryProfile in $AllUserProfilesRegistry) {

            $RegistrySID = $RegistryProfile.PSChildName

            if ($ExcludedLocalSIDs -contains $RegistrySID) {
                Write-Log -Message "Skipping Registry entry $($RegistryProfile.PSChildName) as it is in the exclusion list" -Component ${CmdletName}
            } else {
                Write-Log -Message "Adding Registry entry $($RegistryProfile.PSChildName)" -Component ${CmdletName}
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

                $ProfileData = Format-ProfileData -SID $RegistrySID -Path $RegistryProfile.ProfileImagePath -RegistryLastUseTime (Format-Date -Date $RegistryProfileLoad)

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
                $ProfileData = Format-ProfileData -Path $FileSystemProfile.FullPath -SizeMB $FileSystemProfile.SizeMB
                $ProfileList += $ProfileData
            } elseif ($ProfileList.Path -contains $FileSystemProfile.FullPath) {
                ($ProfileList | Where-Object { $_.Path -eq $FileSystemProfile.FullPath }).SizeMB = "$($FileSystemProfile.SizeMB)"
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
            $LogEventDate = (Format-Date -Date $LogonEvents.TimeCreated)
            Write-Log -Message "Adding logon event for $Username :: $LogEventDate" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"

            if ($ProfileList.Username -notcontains $Username) {
                Write-Log -Message "$Username has a logon event, but does not currently have a profile. Skipping event" -Component ${CmdletName} -ScriptSection "Get-LogonEvents"
            } else {
                try {
                    ($ProfileList | Where-Object { ($_.Username -eq $Username) -and ($_.Domain -eq $Domain) }).EventLogDate = $LogEventDate
                    ($ProfileList | Where-Object { ($_.Username -eq $Username) -and ($_.Domain -eq $Domain) }).EventLogType = $LogonEvents.Type
                } catch {
                    Write-Log -Message "Unable to add event log and event type to $Username" -Severity 2 -Component ${CmdletName}
                }
            }
        }

        # Determine the actions required
        foreach ($Profile in $ProfileList) {
            if ($Profile.SID -eq $Global:VariableTable.ActiveUser.SID) {
                Write-Log -Message "$($Profile.Domain)\$($Profile.username) is the currently logged on user, marking their profile to be ignored" -Component ${CmdletName}
                ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).Action = "Ignore"
                ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = $Profile.EventLogDate
            } else {
                # Check the Event Log Date
                if ($null -eq $Profile.EventLogDate) {
                    # If the Event Log Date is empty, check the registry last use time
                    if ($null -eq $Profile.RegistryLastUseTime) {
                        # If the Registry last use time is empty, check the database
                        if ($DatabaseProfiles.SID -contains $Profile.SID) {
                            # Database contains information about the user
                            if ($null -eq ($DatabaseProfiles | Where-Object { $_.SID -eq $Profile.SID }).LastLogon) {
                                Write-Log -Message "No valid record for $($Profile.SID) can be located. Assigning todays date to begin tracking" -Component ${CmdletName}
                                # The database doesnt contain any information about the users last logon, assigning todays date to begin tracking
                                ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = $TodayString
                            } else {
                                Write-Log -Message "Using the database record for $($Profile.SID) for the last logon of $(($DatabaseProfiles | Where-Object { $_.SID -eq $Profile.SID }).LastLogon)" -Component ${CmdletName}
                                ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = ($DatabaseProfiles | Where-Object { $_.SID -eq $Profile.SID }).LastLogon
                            }
                        } else {
                            Write-Log -Message "No valid record for $($Profile.SID) can be located. Assigning todays date to begin tracking" -Component ${CmdletName}
                            # The database doesnt contain any information about the users last logon, assigning todays date to begin tracking
                            ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = $TodayString
                        }
                    } else {
                        Write-Log -Message "Using the registry value for $($Profile.SID) for last logon" -Component ${CmdletName}

                        # Using the registry last use time as last logon
                        ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = $Profile.RegistryLastUseTime
                    }
                } else {
                    Write-Log -Message "Using the event log value for $($Profile.SID) for last logon" -Component ${CmdletName}
                    ($ProfileList | Where-Object { $_.SID -eq $Profile.SID }).LastLogon = $Profile.EventLogDate
                }
            }
        }

        Write-Output -InputObject $ProfileList
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-LocalUserProfiles

#region Get-RegistryActions
Function Get-RegistryActions {
    <#
.SYNOPSIS
Retrieves a value from the Windows registry based on the specified path and name, with an optional default value if the specified value is not found.

.DESCRIPTION
This function retrieves a value from the Windows registry based on the specified registry path and name. If the specified registry key or value is not found, it optionally creates the key and sets it to a default value specified by the user. The retrieved value is then returned as the output.

.PARAMETER Path
Specifies the registry path from which to retrieve the value.

.PARAMETER Name
Specifies the name of the registry value to retrieve.

.PARAMETER Default
Specifies an optional default value to set if the specified registry value is not found. If not provided, the default behavior is to return $null.

.EXAMPLE
Get-RegistryActions -Path "HKLM:\Software\MyApp" -Name "Settings"

Retrieves the value of the "Settings" registry entry located in the "HKLM:\Software\MyApp" registry path.

.EXAMPLE
Get-RegistryActions -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Default "C:\Wallpapers\default.jpg"

Retrieves the value of the "Wallpaper" registry entry located in the "HKCU:\Control Panel\Desktop" registry path. If the "Wallpaper" entry does not exist, it creates it with the default value "C:\Wallpapers\default.jpg" and returns this value.

.NOTES
This function interacts with the Windows registry to retrieve values. It can be useful for reading and managing registry settings within PowerShell scripts or functions.

#>
    Param ($Path, $Name, $Default = $false
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Write-Log -Message "Obtaining information from reg key $Path with value $Name" -Component ${CmdletName}
        if (Test-Path $Path) {
            Write-Log -Message "$Path found, attempting to get value $Name" -Component ${CmdletName}
            try {
                $TempReturn = (Get-ItemPropertyValue -Path $Path -Name "$Name")
                if ($null -eq $TempReturn.$Name) {
                    $ReturnObject = $TempReturn
                } else {
                    $ReturnObject = $TempReturn.$Name
                }
            } catch {
                New-ItemProperty -Path $Path -Name "$Name" -Value "$Default"
                $ReturnObject = $Default
            }
        } else {
            $ReturnObject = $Default
        }
        Write-Log -Message "Returning $ReturnObject" -Component ${CmdletName}
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-RegistryActions

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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
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
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-UserName

#region Get-WS1DeviceInformation
Function Get-WS1DeviceInformation {
    <#
.SYNOPSIS
    Retrieves information about Workspace ONE devices based on various parameters like device name, serial number, or all devices.

.DESCRIPTION
    The Get-WS1DeviceInformation function retrieves information about Workspace ONE devices based on different search criteria:
    - AllDevices: Retrieves information about all devices registered in Workspace ONE.
    - DeviceName: Retrieves information about a specific device by its name.
    - SerialNumber: Retrieves information about a device using its serial number.
    - LocalDevice: Retrieves information about the local device where the script is executed.

.PARAMETER AllDevices
    Specifies to retrieve information about all devices registered in Workspace ONE.

.PARAMETER DeviceName
    Specifies the name of the device to retrieve information for.

.PARAMETER SerialNumber
    Specifies the serial number of the device to retrieve information for.

.PARAMETER LocalDevice
    Specifies to retrieve information about the local device where the script is executed.

.EXAMPLE
    Get-WS1DeviceInformation -AllDevices
    Retrieves information about all devices registered in Workspace ONE.

.EXAMPLE
    Get-WS1DeviceInformation -DeviceName "Device01"
    Retrieves information about a specific device named "Device01" from Workspace ONE.

.EXAMPLE
    Get-WS1DeviceInformation -SerialNumber "ABC123"
    Retrieves information about a device with the serial number "ABC123" from Workspace ONE.

.NOTES

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ParameterSetName = 'AllDevices')]
        [switch]$AllDevices,
        [Parameter(Mandatory, ParameterSetName = 'DeviceName')]
        [string]$DeviceName,
        [Parameter(Mandatory, ParameterSetName = 'SerialNumber')]
        [string]$SerialNumber,
        [Parameter(Mandatory, ParameterSetName = 'LocalDevice')]
        [switch]$LocalDevice,
        [Parameter(Mandatory, ParameterSetName = 'UUID')]
        [string]$UUID
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Write-Log -Message "Retrieving device information, there is potential that this could take a while." -Component ${CmdletName}
        $SerialNumberURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.DeviceSearchSerialNumber.URL
            Header = switch ($Global:VariableTable.API.Endpoints.DeviceSearchSerialNumber.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.DeviceSearchSerialNumber.Method
        }

        $AllDevicesURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.DeviceSearch.URL
            Header = switch ($Global:VariableTable.API.Endpoints.DeviceSearch.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.DeviceSearch.Method
        }

        if ($Global:VariableTable.API.PageSize) {
            [int]$PageSize = $Global:VariableTable.API.PageSize
        } else {
            [int]$PageSize = 500
        }

        [int]$pageNumber = -1

        try {
            if ($LocalDevice.IsPresent) {
                Try {
                    $Devicename = $ENV:ComputerName
                    $SerialNumber = $Global:VariableTable.Device.SerialNumber
                    if ($null -eq $SerialNumber) {
                        $SerialNumber = (Get-CimInstance -ClassName Win32_Bios).SerialNumber
                    }
                    if ($DeviceSerial -like "* *") {
                        $DeviceSerial = $DeviceSerial.Replace(" ", "+")
                    }
                    $SearchMode = "SerialNumber"
                } catch {
                    Write-Log -Message "An error occured trying to define the serial number for this device. Defaulting to searching for the device via its name" -Severity 2 -Component ${CmdletName}
                    $Devicename = $ENV:ComputerName
                    $SearchMode = "DeviceName"
                }
            } elseif ($AllDevices.IsPresent) {
                $SearchMode = "AllDevices"
            } elseif ($null -ne $DeviceName) {
                $Online = Get-OnlineStatus -DeviceName $DeviceName -Quiet

                if ($Online -eq $true) {
                    try {
                        $DeviceSerial = (Invoke-Command -ScriptBlock { Get-WmiObject win32_bios | Select-Object Serialnumber } -ComputerName $DeviceName).SerialNumber
                        if ($null -eq $SerialNumber) {
                            $SerialNumber = (Get-CimInstance -ClassName Win32_Bios).SerialNumber
                        }
                        if ($DeviceSerial -like "* *") {
                            $DeviceSerial = $DeviceSerial.Replace(" ", "+")
                        }
                        $SearchMode = "SerialNumber"
                    } catch {
                        Write-Log -Message "An error occured trying to define the serial number for this device. Defaulting to searching for the device via its name" -Severity 2 -Component ${CmdletName}
                        $SearchMode = "DeviceName"
                    }
                } else {
                    $SearchMode = "DeviceName"
                }
            } else {
                Write-Log -Message "No mode was selected, defaulting to return all devices" -Severity 2 -Component ${CmdletName}
                $SearchMode = "AllDevices"
            }
            Write-Log -Message "Search Mode :: $SearchMode" -DebugMessage -Component ${CmdletName}

            switch ($SearchMode) {
                DeviceName {
                    # Get all devices
                    $Response = Get-WS1DeviceInformation -AllDevices

                    # Search through all the devices for the name
                    if ($Response.DeviceFriendlyName -contains $DeviceName) {
                        $ReturnObject = $Response | Where-Object { $_.DeviceFriendlyName -eq $DeviceName }
                    } elseif ($Response.Device_Friendly_Name -contains $DeviceName) {
                        $ReturnObject = $Response | Where-Object { $_.Device_Friendly_Name -eq $DeviceName }
                    } else {
                        Write-Log -Message "Unable to locate $DeviceName within Workspace ONE." -Severity 3 -Component ${CmdletName}
                        $ReturnObject = $null
                    }
                }
                AllDevices {
                    $AllDevicesDetails = @()
                    do {
                        $ExitLoop = $false
                        $PageNumber++
                        $url = ($AllDevicesURL.URL.Replace("##PageSize##", $PageSize)).Replace("##PageNumber##", $PageNumber)
                        $Method = $AllDevicesURL.Method
                        $header = $AllDevicesURL.Header

                        Write-Log -Message "URL: $($url.toString())" -Component ${CmdletName} -DebugMessage
                        Write-Log -Message "Method: $($Method)" -Component ${CmdletName} -DebugMessage
                        Write-Log -Message "Header Auth: $($Header.Authorization)" -Component ${CmdletName} -DebugMessage
                        Write-Log -Message "Header aw-tenant-code: $($Header.'aw-tenant-code')" -Component ${CmdletName} -DebugMessage

                        [int]$AttemptCount = 0
                        do {
                            $AttemptCount++
                            try {
                                Write-Log -Message "$($url.ToString())" -Component ${CmdletName} -DebugMessage
                                $response = Invoke-RestMethod -Method $Method -Uri $url.ToString() -Headers $Header -TimeoutSec $RestMethodTimeout
                            } catch {
                                Write-Log -Message "Error getting API... waiting 30 seconds and trying again" -Component ${CmdletName} -Severity 1
                                [bool]$innerLoopEnd = $false
                                Start-Sleep -Seconds 30
                                if ($AttemptCount -gt 10) {
                                    Write-Log -Message "Unable to obtain a successful API call after more than 10 attempts. Exiting script" -Component ${CmdletName} -Severity 1
                                    [bool]$innerLoopEnd = $True
                                    throw
                                }
                            }

                            if ($null -ne $response) {
                                [bool]$innerLoopEnd = $true
                            }

                        } until (
                            $innerLoopEnd -eq $true
                        )

                        $AllDevicesDetails += $response
                        Write-Log -Message "Devices Found :: $($AllDevicesDetails.Devices.Count)/$($Response.Total) after $($PageNumber + 1) queries" -DebugMessage -Component ${CmdletName}
                        if ($AllDevicesDetails.Devices.Count -ge $Response.Total) {
                            $ExitLoop = $True
                        }

                        $ReturnObject = $AllDevicesDetails.Devices

                    } until (
                        $ExitLoop -eq $true
                    )
                }
                SerialNumber {
                    $url = $SerialNumberURL.URL.Replace("##SerialNumber##", $SerialNumber)
                    $Method = $SerialNumberURL.Method
                    $header = $SerialNumberURL.Header
                    try {
                        $Response = Invoke-RestMethod -Method $Method -Uri $url.ToString() -Headers $Header -TimeoutSec $RestMethodTimeout
                    } catch {
                        $ErrorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
                        if ($ErrorMessage.message -eq "Device not found for specified identifier") {
                            Write-Log -Message "Error getting API... Unable to find device via the given perameters" -Component ${CmdletName} -Severity 1
                            $Response = $null
                        } else {
                            Write-Log -Message "Error getting API... Unable to find device via the API for serial numbers. Will attempt to search via all devices" -Component ${CmdletName} -Severity 2

                        }
                    }

                    $ReturnObject = $Response

                }
                Default {
                    Write-Log -Message "An error occured, returning a null value" -Severity 3 -Component ${CmdletName}
                    $ReturnObject = $null
                }
            }

            if ($null -eq $ReturnObject) {
                Write-Log -Message "No valid response was recieved for the primary search criteria. Expanding the search in an attempt to locate the device. This might take a while" -Component ${CmdletName}
                $Response = Get-WS1DeviceInformation -AllDevices
                $Global:AllDevices = $Response
                # Search through all the devices for the serial number
                if ($Response.SerialNumber -contains $SerialNumber) {
                    $ReturnObject = $Response | Where-Object { $_.SerialNumber -eq $SerialNumber }
                } elseif ($Response.DeviceFriendlyName -contains $DeviceName) {
                    $ReturnObject = $Response | Where-Object { $_.DeviceFriendlyName -eq $DeviceName }
                } elseif ($Response.Device_Friendly_Name -contains $DeviceName) {
                    $ReturnObject = $Response | Where-Object { $_.Device_Friendly_Name -eq $DeviceName }
                } else {
                    Write-Log -Message "Unable to locate the device within Workspace ONE via serial number ($SerialNumber) or device name ($DeviceName)." -Severity 3 -Component ${CmdletName}
                    $ReturnObject = $null
                }

            }

            if ($ReturnObject.DeviceFriendlyName) {
                $ReturnCount = $ReturnObject.DeviceFriendlyName.Count
            } else {
                $ReturnCount = $ReturnObject.Device_Friendly_Name.Count
            }

            Write-Log -Message "Devices found :: $($ReturnCount)" -Component ${CmdletName}
            Write-Output -InputObject $ReturnObject
        } catch {
            Write-Log -Message "An error occured trying to get the device by Udid. Exception: $($_.Exception.Message)" -Component ${CmdletName}
            Write-Output -InputObject $null
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-WS1DeviceInformation

#region Get-DeviceProfiles
Function Get-WS1DeviceProfiles {
    <#
.SYNOPSIS
    Retrieves device profiles by ID using the WS1 API
.DESCRIPTION
    The Get-WS1DeviceProfiles function is used to retrieve device profiles by ID. The function takes one parameter, $DeviceID, which is the ID of the device for which the profiles should be retrieved.

.EXAMPLE
    Get-WS1DeviceProfiles -DeviceID "12345"
    This will retrieve the device profiles for the device with ID "12345" and return the profiles in the form of $ReturnObject.
.NOTES
    This function requires the WS1 API endpoint and authentication information to be configured in the global variable table before it can be used.
    Make sure to handle the cases of null responses and errors correctly in the script that calls this function.
    This function will log messages for debugging purposes, make sure to check the log before running the script in production.
#>
    Param ([string]$DeviceID = $Global:VariableTable.Device.ID
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $DeviceProfileURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.DeviceProfiles.URL
            Header = switch ($Global:VariableTable.API.Endpoints.DeviceProfiles.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.DeviceProfiles.Method
        }

        try {
            $url = $DeviceProfileURL.URL.Replace("##DeviceID##", $DeviceID)
            Write-Log -Message "URL: $($url.toString())" -Component ${CmdletName} -DebugMessage
            Write-Log -Message "Method: $($DeviceProfileURL.Method)" -Component ${CmdletName} -DebugMessage
            $Count = 0
            do {
                $Count++
                try {
                    Write-Log -Message "$($url.ToString())" -Component ${CmdletName} -DebugMessage
                    $response = Invoke-RestMethod -Method $DeviceProfileURL.Method -Uri $url.ToString() -Headers $DeviceProfileURL.Header -TimeoutSec $RestMethodTimeout

                    $innerLoopEnd = $true
                    Write-Log -Message "APIs took $count attempts" -Component ${CmdletName} -DebugMessage
                } catch {
                    Write-Log -Message "Error getting API... waiting 30 seconds and trying again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $false
                    Start-Sleep -Seconds 30

                }

                if ($Count -gt 10) {
                    Write-Log -Message "Unable to obtain a successful API call after more than 10 attempts. Exiting script and will try again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $True
                    throw
                }
            } until (
                $innerLoopEnd -eq $true
            )

            if ($null -eq $Response) {
                Write-Log -Message "No profiles were returned for this device" -Component ${CmdletName}
            } else {
                Write-Log -Message "$($response.DeviceProfiles.Count) profiles returned for this device" -Component ${CmdletName}
                $ReturnObject = $response
            }
        } catch {
            Write-Log -Message "An error occured trying to get the device profiles by ID. Exception: $($_.Exception.Message)" -Component ${CmdletName}
            $ReturnObject = $null
        }
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DeviceProfiles

#region Get-WS1DeviceTags
Function Get-WS1DeviceTags {
    <#
.SYNOPSIS
    The Get-WS1DeviceTags cmdlet retrieves the tags for a specific device identified by its UUID.
.DESCRIPTION
    This cmdlet uses the Invoke-RestMethod cmdlet to call an API endpoint and retrieve the tags for a device.

.PARAMETER DeviceUUID
    The UUID of the device for which the tags are being retrieved. This parameter is required and defaults to the value of the global variable $Global:VariableTable.Device.UUID.

.EXAMPLE
    Get-WS1DeviceTags -DeviceUUID "12345678-1234-1234-1234-123456789abc"

    This example retrieves the tags for the device with the UUID "12345678-1234-1234-1234-123456789abc".

.NOTES
    If the API call is successful, the tags are returned in a response object, which is logged and output.
    If the API call is not successful, an exception message is logged and null is output.
    The function also uses Write-FunctionHeaderOrFooter and Write-Log to log actions and errors.
    It's important to check the API endpoint, headers and method to use the correct one.
#>
    Param ($DeviceUUID = $Global:VariableTable.Device.DeviceUUID
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $DeviceTagURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.DeviceTags.URL
            Header = switch ($Global:VariableTable.API.Endpoints.DeviceTags.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.DeviceTags.Method
        }

        try {
            $url = $DeviceTagURL.URL.Replace("##DeviceUUID##", $DeviceUUID)
            Write-Log -Message "URL: $($url.toString())" -Component ${CmdletName} -DebugMessage
            Write-Log -Message "Method: $($DeviceTagURL.Method)" -Component ${CmdletName} -DebugMessage
            $Count = 0
            do {
                $Count++
                try {
                    Write-Log -Message "$($url.ToString())" -Component ${CmdletName} -DebugMessage
                    $response = Invoke-RestMethod -Method $DeviceTagURL.Method -Uri $url.ToString() -Headers $DeviceTagURL.Header -TimeoutSec $RestMethodTimeout

                    $innerLoopEnd = $true
                    Write-Log -Message "APIs took $count attempts" -Component ${CmdletName} -DebugMessage
                } catch {
                    Write-Log -Message "Error getting API... waiting 30 seconds and trying again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $false
                    Start-Sleep -Seconds 30

                }

                if ($Count -gt 10) {
                    Write-Log -Message "Unable to obtain a successful API call after more than 10 attempts. Exiting script and will try again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $True
                    throw
                }
            } until (
                $innerLoopEnd -eq $true
            )
            if ($null -eq $Response) {
                Write-Log -Message "No tags were returned for this device" -Component ${CmdletName}
            } else {
                Write-Log -Message "$($response.tags.Count) tags returned for this device" -Component ${CmdletName}
                $ReturnObject = $response
            }
        } catch {
            Write-Log -Message "An error occured trying to get the device tags by Udid. Exception: $($_.Exception.Message)" -Component ${CmdletName}
            $ReturnObject = $null
        }
        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-WS1DeviceTags

#region Get-WS1UserInformation
Function Get-WS1UserInformation {
    <#
.SYNOPSIS
    This function retrieves information about a user in an API by searching for the provided username.
.DESCRIPTION
    The function takes in two parameters: the username of the user to search for, and a switch parameter that controls whether or not to return multiple users if multiple users are found with the same username.
.PARAMETER username
    String: The username of the user to search for.

.PARAMETER return
    Switch: Controls whether or not to return multiple users if multiple users are found with the same username.

.EXAMPLE
    Get-WS1UserInformation -username "JohnDoe" -return

    This example retrieves information about the user with the username "JohnDoe" and returns all users if multiple users are found with the same username.

.NOTES
    This function relies on the presence of the "Write-FunctionHeaderOrFooter" and "Write-Log" functions, as well as a "VariableTable" global variable that contains the API endpoint URL, headers, and method for searching for users by their username.

#>
    Param ([string]$username, [switch]$return
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $UsernameURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.UserSearchUsername.URL
            Header = switch ($Global:VariableTable.API.Endpoints.UserSearchUsername.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.UserSearchUsername.Method
        }

        try {
            $url = $UsernameURL.URL.Replace("##Username##", $username)
            Write-Log -Message "URL: $($url.ToString())" -Component ${CmdletName} -DebugMessage
            $Count = 0
            do {
                $Count++
                try {
                    Write-Log -Message "$($url.ToString())" -Component ${CmdletName} -DebugMessage
                    $response = Invoke-RestMethod -Method $UsernameURL.Method -Uri $url.ToString() -Headers $UsernameURL.Header -TimeoutSec $RestMethodTimeout

                    $innerLoopEnd = $true
                    Write-Log -Message "APIs took $count attempts" -Component ${CmdletName} -DebugMessage
                } catch {
                    Write-Log -Message "Error getting API... waiting 30 seconds and trying again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $false
                    Start-Sleep -Seconds 30

                }

                if ($Count -gt 10) {
                    Write-Log -Message "Unable to obtain a successful API call after more than 10 attempts. Exiting script and will try again" -Component ${CmdletName} -Severity 1
                    $innerLoopEnd = $True
                    throw
                }
            } until (
                $innerLoopEnd -eq $true
            )
            if ($response.Users.Count -gt 1) {
                Write-Log -Message "Multiple users returned, attempting to separate the accounts" -Component ${CmdletName}
                $TempResponse = ($response.Users | Where-Object { ($_.Username -ceq $Username) })
                if ($TempResponse.Username.Count -eq 1) {
                    Write-Log -Message "Single user found, returning information" -Component ${CmdletName}
                    $ReturnObject = [PSCustomObject]@{
                        Username = $TempResponse.Username
                        UserID   = $TempResponse.ID.value
                        UPN      = $TempResponse.Email
                    }
                } elseif ($return) {
                    Write-Log -Message "Unable to separate the users, returning all users" -Component ${CmdletName}
                    $ReturnObject = @()
                    foreach ($user in $Response.Users) {
                        $ReturnObject += [PSCustomObject]@{
                            Username = $user.Username
                            UserID   = $user.ID.value
                            UPN      = $user.Email
                        }
                    }
                } else {
                    Write-Log -Message "Unable to separate the users, returning nothing" -Component ${CmdletName}
                    $ReturnObject = $null
                }
            } elseif ($null -eq $Response) {
                Write-Log -Message "No user accounts returned" -Component ${CmdletName}
                $ReturnObject = $null
            } else {
                Write-Log -Message "Single user found, returning information" -Component ${CmdletName}
                $ReturnObject = [PSCustomObject]@{
                    Username = $Response.Users.Username
                    UserID   = $response.Users.ID.value
                    UPN      = $Response.Users.Email
                }
            }
            Write-Output -InputObject $ReturnObject
        } catch {
            Write-Log -Message "Unable to retrieve information" -Component ${CmdletName}
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-WS1UserInformation



#region Initialize-DiskCleanup
Function Initialize-DiskCleanup {
    <#
.SYNOPSIS
Initiates disk cleanup operations on the system.

.DESCRIPTION
This function performs various disk cleanup operations on the system to free up disk space. It clears temporary files, cleans the recycle bin, cleans browser logs, removes crash dump files, clears user temp files, and performs other cleanup tasks based on configured settings. It also updates disk space information before and after the cleanup operation in the database or registry for reporting purposes.

.EXAMPLE
Initialize-DiskCleanup

.NOTES
This function is typically used to automate disk cleanup tasks and manage disk space on a system.
#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Global:ScriptSection = "Free Space Check"
        if ($IsTesting -eq $true) {
            Write-Log -Message "Creating temp files for clean testing" -Component ${CmdletName}
            New-TempFiles -Path "C:\Temp\Tempfiles" -Size 1GB
        }

        # Get the current disk space and write it to the database
        $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive
        Update-DatabaseDiskSpaceEntry -Mode "DiskCleanup" -CollectedInformation $DiskStatistics -Status "Start"

        if ($IsTesting -eq $true) {
            Write-Log -Message "Performing test cleaning" -Component ${CmdletName}
            if (Test-Path -Path "C:\Temp\Tempfiles\TempFile.txt") {
                Clear-Folder -FilePath "C:\Temp\Tempfiles"
            }
        } else {
            #Cleaning disk

            #Clean recycle bin
            $Global:ScriptSection = "Recycle Bin"
            Write-Log -Message "Cleaning Recycle Bin" -Component ${CmdletName}
            Clear-RecycleBin -DriveLetter $ENV:SystemDrive -Force -ErrorAction SilentlyContinue

            [string]$RegistryPath = (Convert-RegistryPath -Key "$($Global:VariableTable.RegKeyPaths.Agency)\HealthCheck\DiskCleanup")
            # Gets the registry key switches to determine what actions to take
            [string]$Global:ScriptSection = "Action Switches"
            [string]$CleanCache = Get-RegistryActions -Path "$RegistryPath" -Name "CleanCache"
            [string]$CleanTemp = Get-RegistryActions -Path $RegistryPath -Name "CleanTemp"
            [string]$CleanWinDirTemp = Get-RegistryActions -Path $RegistryPath -Name "CleanWinDirTemp" -Default "True"
            [string]$CleanGoogleBrowserSwitch = Get-RegistryActions -Path $RegistryPath -Name "CleanGoogleBrowserSwitch" -Default "True"
            [string]$CleanCrashDump = Get-RegistryActions -Path $RegistryPath -Name "CleanCrashDump" -Default "True"
            [string]$CleanUserTemp = Get-RegistryActions -Path $RegistryPath -Name "CleanUserTemp" -Default "True"
            [string]$CleanWS1BridgeLog = Get-RegistryActions -Path $RegistryPath -Name "CleanWS1BridgeLog" -Default "True"
            [string]$CleanWinSXS = Get-RegistryActions -Path $RegistryPath -Name "CleanWinSXS" -Default "True"
            [string]$RunDiskCleanupUtility = Get-RegistryActions -Path $RegistryPath -Name "RunDiskCleanupUtility" -Default "False"
            [string]$CleanOST = Get-RegistryActions -Path $RegistryPath -Name "CleanOST" -Default "False"
            [string]$CleanPath = Get-RegistryActions -Path $RegistryPath -Name "CleanPath" -Default "C:\LocalCustom|C:\_UA_InstalledAppExport|C:\_Provisioning|C:\Drivers"
            [string]$CleanPathTemp = Get-RegistryActions -Path $RegistryPath -Name "CleanPathTemp"

            # Clean application deployment cache
            switch ($Global:VariableTable.Device.Management) {
                WS1 {
                    $CachePath = "$($Global:VariableTable.FileLocations.WS1Cache)"
                }
                SCCM {
                    $CachePath = "$($Global:VariableTable.FileLocations.SCCMCache))"
                }
                Default {}
            }

            $FolderPath = "$CachePath"
            $Global:ScriptSection = "Cache Cleaning"

            switch ($CleanCache.ToLower()) {
                true {
                    Write-Log -Message "Proceeding to clear $FolderPath of items older than 30 days" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -Age 30
                }
                force {
                    Write-Log -Message "Proceeding to clear $FolderPath of ALL items" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -force
                }
                false { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
            }

            # Clean $ENV:SystemDrive\Temp
            $Global:ScriptSection = "Temporary File Cleaning"
            $FolderPath = "$ENV:SystemDrive\Temp"
            switch ($CleanTemp.ToLower()) {
                true {
                    Write-Log -Message "Proceeding to clear $FolderPath of items older than 30 days" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -Age 30
                }
                force {
                    Write-Log -Message "Proceeding to clear $FolderPath of ALL items" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -force
                }
                false { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
            }

            # Clean $ENV:windir\Temp
            $FolderPath = "$ENV:windir\Temp"
            switch ($CleanWinDirTemp.ToLower()) {
                true {
                    Write-Log -Message "Proceeding to clear $FolderPath of items older than 30 days" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -Age 30
                }
                force {
                    Write-Log -Message "Proceeding to clear $FolderPath of ALL items" -Component ${CmdletName}
                    Clear-Folder -Path $FolderPath -force
                }
                false { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "$FolderPath cleaning disabled" -Component ${CmdletName} }
            }

            # Clean Google Browser Switcher Log
            $Global:ScriptSection = "User File Cleanup"

            Write-Log -Message "Getting list of users" -Component ${CmdletName}
            $AllUserProfilesFileSystem = Get-FolderSize -BasePath "$ENV:SystemDrive\Users"
            switch ($CleanGoogleBrowserSwitch) {
                true {
                    Write-Log -Message "Proceeding to clear $FolderPath of items older than 30 days" -Component ${CmdletName}
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for BrowserSwitcher Log" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Google\BrowserSwitcher\native_log.txt") {
                            Write-Log -Message "BrowserSwitcher Log found in profile, removing log" -Component ${CmdletName}
                            Remove-Item -Path "$($Profile.FullPath)\AppData\Local\Google\BrowserSwitcher\native_log.txt" -Force
                        }
                    }
                }
                false { Write-Log -Message "Google Browser Switching log cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "Google Browser switching log cleaning disabled" -Component ${CmdletName} }
            }

            # Clean Crash dump files
            $Global:ScriptSection = "Crash Dump Cleanup"
            switch ($CleanCrashDump) {
                true {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for crash dump files" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\CrashDumps") {
                            Write-Log -Message "CrashDumps folder found in profile, removing files" -Component ${CmdletName}
                            Clear-Folder -Path "$($Profile.FullPath)\AppData\Local\CrashDumps" -Force
                        }
                    }
                }
                false { Write-Log -Message "Crash dump cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "Crash dump cleaning disabled" -Component ${CmdletName} }
            }

            # Clean user temp files
            $Global:ScriptSection = "User Temp Cleanup"

            switch ($CleanUserTemp) {
                true {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for local temp files older than 30 days" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Temp") {
                            Write-Log -Message "User temp files found in profile, removing files older than 30 days" -Component ${CmdletName}
                            Clear-Folder -Path "$($Profile.FullPath)\AppData\Local\Temp" -Age 30
                        }
                    }
                }
                force {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for local temp files" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Temp") {
                            Write-Log -Message "User temp files found in profile, removing files" -Component ${CmdletName}
                            Clear-Folder -Path "$($Profile.FullPath)\AppData\Local\Temp"
                        }
                    }
                }
                false { Write-Log -Message "User Temp file cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "User Temp file cleaning disabled" -Component ${CmdletName} }
            }

            # Clean user OST files
            $Global:ScriptSection = "User OST Cleanup"

            switch ($CleanOST) {
                true {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for OST files" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Microsoft\Outlook") {
                            Write-Log -Message "OST found in $($Profile.FolderName), removing file" -Component ${CmdletName}
                            $OSTs = Get-Item -Path "$($Profile.FullPath)\AppData\Local\Microsoft\Outlook\*" -Filter "*.ost"
                            foreach ($OST in $OSTs) {
                                Remove-Item -Path "$($OST.FullName)" -Force
                            }
                        }
                    }
                }
                force {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for local temp files" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Temp") {
                            Write-Log -Message "User temp files found in profile, removing files" -Component ${CmdletName}
                            Clear-Folder -Path "$($Profile.FullPath)\AppData\Local\Temp"
                        }
                    }
                }
                false { Write-Log -Message "OST file cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "OST file cleaning disabled" -Component ${CmdletName} }
            }

            # Clean Workspace ONE Bridge log file
            $Global:ScriptSection = "Workspace ONE Bridge Cleanup"

            switch ($CleanWS1BridgeLog) {
                true {
                    foreach ($Profile in $AllUserProfilesFileSystem) {
                        Write-Log -Message "Checking $($Profile.FolderName) for WS1 Bridge log files" -Component ${CmdletName}
                        if (Test-Path -Path "$($Profile.FullPath)\AppData\Local\Packages") {
                            $WS1Logs = Get-ChildItem "$($Profile.FullPath)\AppData\Local\Packages\*" -Recurse -Include WS1_Bridge*.log
                            foreach ($WS1logfile in $WS1Logs) {
                                Remove-Item $WS1logfile -Force
                            }
                        }
                    }
                }
                false { Write-Log -Message "WS1 bridge log file cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "WS1 bridge log file cleaning disabled" -Component ${CmdletName} }
            }

            # Clean WinSXS
            $Global:ScriptSection = "Windows SXS Cleanup"

            switch ($CleanWinSXS) {
                true {
                    $DeployImgSerManEXE = "C:\WINDOWS\System32\Dism.exe"
                    If (Test-Path $DeployImgSerManEXE) {
                        Write-Log -Message "Running Deployment Image Servicing and Management command to reduce the WinSXS folder size" -Component ${CmdletName}
                        Start-Process $DeployImgSerManEXE -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -WindowStyle Hidden
                    }
                }
                false { Write-Log -Message "WinSXS folder cleaning disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "WinSXS folder cleaning disabled" -Component ${CmdletName} }
            }

            # Run Windows Disk Cleanup utility
            $Global:ScriptSection = "Windows Disk Cleanup"

            switch ($RunDiskCleanupUtility) {
                true {
                    $Global:ScriptSection = "Disk Cleanup Tool"
                    $SubKeys = "Active Setup Temp Folders",
                    "BranchCache",
                    "Content Indexer Cleaner",
                    "D3D Shader Cache",
                    "Downloaded Program Files",
                    "Delivery Optimization Files",
                    "Device Driver Packages",
                    "Diagnostic Data Viewer database files",
                    "Internet Cache Files",
                    "Language Pack",
                    "Offline Pages Files",
                    "Old ChkDsk Files",
                    "Previous Installations",
                    "Recycle Bin",
                    "Setup Log Files",
                    "System error memory dump files",
                    "System error minidump files",
                    "Temporary Files",
                    "Temporary Setup Files",
                    "Temporary Sync Files",
                    "Thumbnail Cache",
                    "Update Cleanup",
                    "Upgrade Discarded Files",
                    "Windows Defender",
                    "Windows Error Reporting Files",
                    "Windows ESD installation files"

                    $RegPath = "$($Global:VariableTable.RegKeyPaths.VolumeCaches)"

                    Foreach ($Key in $SubKeys) {

                        if ((Test-Path -Path "$RegPath\$Key")) {
                            if (!(Get-ItemProperty -Path "$RegPath\$Key\" -Name StateFlags0100)) {
                                New-ItemProperty -Path "$RegPath\$Key" -Name StateFlags0100 -PropertyType DWORD -Value 2
                            } else {
                                Set-ItemProperty -Path "$RegPath\$Key" -Name StateFlags0100 -Value 2
                            }
                        }
                    }

                    $CleanMgrEXE = "C:\WINDOWS\System32\cleanmgr.exe"
                    If (Test-Path $CleanMgrEXE) {
                        Write-Log -Message "Running Windows Disk Cleanup" -Component ${CmdletName}
                        Invoke-Process -Path 'C:\WINDOWS\System32\cleanmgr.exe' -Parameters '/sagerun:100' -WindowStyle Hidden -NoWait
                        Write-Log -Message "Waiting for up to 30 minutes for Disk Cleanup to finish" -Component ${CmdletName}
                        for ($i = 0; $i -lt 30; $i++) {
                            Start-Sleep -Seconds 60
                            try {
                                Write-Log -Message "Checking if the proces is still running" -Component ${CmdletName}
                                $Processes = Get-Process -Name "cleanmgr"
                            } catch {
                                $Processes = $false
                            }

                            if ($Processes -eq $false) {
                                $i = 31
                                Write-Log -Message "Windows Disk Cleanup Finished" -Component ${CmdletName}
                            }

                            if ($i -eq 30) {
                                Write-Log -Message "Windows Disk Cleanup has not completed within 30 minutes, continuing with clean up" -Component ${CmdletName}
                            }
                        }
                    }

                }
                false { Write-Log -Message "Running Windows disk clean up utility disabled" -Component ${CmdletName} }
                Default { Write-Log -Message "Running Windows disk clean up utility disabled" -Component ${CmdletName} }
            }

            #Clean Custom Path
            $Global:ScriptSection = "Clean Custom Paths"
            if ($null -ne $CleanPath) {
                $TempCleanPaths = $CleanPath.Split("|")
                foreach ($CustomPath in $TempCleanPaths) {}
                Write-Log -Message "Checking $CustomPath" -Component ${CmdletName}
                if (Test-Path -Path "$CustomPath") {
                    Write-Log -Message "$CustomPath exists, cleaning contents" -Component ${CmdletName}
                    Clear-Folder -Path "$CustomPath" -Force
                }
            }
            #Clean Custom Path

            #Clean Custom Path
            $Global:ScriptSection = "Clean Temporary Custom Paths"
            if ($null -ne $CleanPathTemp) {
                $TempCleanPaths = $CleanPathTemp.Split("|")
                foreach ($CustomPath in $TempCleanPaths) {}
                Write-Log -Message "Checking $CustomPath" -Component ${CmdletName}
                if (Test-Path -Path "$CustomPath") {
                    Write-Log -Message "$CustomPath exists, cleaning contents" -Component ${CmdletName}
                    Clear-Folder -Path "$CustomPath" -Force
                    #TODO Remove entry from the registry.... somehow
                }
            }

        }
        $Global:ScriptSection = "Post Result Recording"

        $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive
        Update-DatabaseDiskSpaceEntry -Mode "DiskCleanup" -CollectedInformation $DiskStatistics -Status "Completed"

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialize-DiskCleanup



#region Initialize-ProfileCleanup
Function Initialize-ProfileCleanup {
    <#
.SYNOPSIS
Initializes the cleanup process for user profiles on a system.

.DESCRIPTION
This function is designed to assess and clean up user profiles on a computer based on specific criteria such as age and usage. It integrates with a database for logging purposes and supports running in a test mode for validation purposes without making actual changes.

.EXAMPLE
Initialize-ProfileCleanup

Executes the profile cleanup process based on predefined criteria and logs the actions.

.NOTES
This function is part of a larger system management script and relies on several global variables and other custom functions like Get-DiskSpace, Update-DatabaseDiskSpaceEntry, Get-DatabaseEntry, and Write-Log. Ensure these components are available and properly configured before using this function.

The function iterates through user profiles, assesses them based on various factors such as last logon time, username, and profile size, and determines an action to take for each profile. Actions include cleaning, deleting, ignoring, or marking profiles as orphaned. It then performs the defined actions, such as removing desktop, downloads, and temporary files, as well as deleting orphans or profiles marked for deletion.

Once the cleanup actions are completed, the function checks for the successful removal of profiles and updates the database accordingly. It also logs disk space information before and after the cleanup process.

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if ($IsTesting -eq $true) {
            Write-Log -Message "Creating temp files for clean testing" -Component ${CmdletName}
            New-TempFiles -Path "C:\Temp\Tempfiles" -Size 1GB
        }

        [string]$RegistryPath = "$($Global:VariableTable.RegKeyPaths.HealthCheck.ProfileCleanup)"
        [array]$ExcludedUserNames = $Global:VariableTable.Users.ExcludedUserNames

        # Get the current disk space and write it to the database
        $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive
        Update-DatabaseDiskSpaceEntry -Mode "ProfileCleanup" -CollectedInformation $DiskStatistics -Status "Start"

        $CurrentDiskSpaceDatabaseEntry = (Get-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace") | Where-Object { ($_.Action -eq "ProfileCleanup") -and ($_.Status -eq "Start") }

        Write-Log -Message "Total Free Space: $($DiskStatistics.FreeSpace) GB" -Component ${CmdletName}
        Write-Log -Message "Total Free Space Percentage: $($DiskStatistics.FreePercentage)%" -Component ${CmdletName}
        Write-Log -Message "Current Total Space Cleaned: $($CurrentDiskSpaceDatabaseEntry.TotalClearedSpace) GB" -Component ${CmdletName}

        if ($IsTesting -eq $true) {
            Write-Log -Message "Performing test cleaning" -Component ${CmdletName}
            if (Test-Path -Path "C:\Temp\Tempfiles\TempFile.txt") {
                Remove-Item -Path "C:\Temp\Tempfiles\TempFile.txt"
            }
        }

        $TempLocalUserProfiles = Get-LocalUserProfiles
        $RegistryPath = "$($Global:VariableTable.RegKeyPaths.HealthCheck)\ProfileCleanup"
        $Global:ScriptSection = "Action Switches"
        [string]$ProfileAge = Get-RegistryActions -Path "$RegistryPath" -Name "ProfileAge" -Default "30"
        [Int32]$ProfileGrace = Get-RegistryActions -Path "$RegistryPath" -Name "ProfileGrace" -Default "14"


        $LocalUserProfiles = @()

        foreach ($tempprofile in $TempLocalUserProfiles) {
            if ($null -ne $tempProfile) {
                $LocalUserProfiles += $tempprofile
            }
        }

        [int32]$MaxUserNameLength = 0
        foreach ($Profile in $LocalUserProfiles) {
            if (($Profile.Username).Length -gt $MaxUserNameLength) {
                $MaxUserNameLength = ($Profile.Username).Length
            }
        }

        foreach ($Profile in $LocalUserProfiles) {

            $DateDifference = New-TimeSpan $Profile.LastLogon -End $TodayString
            $DaysSinceLogon = [int]$DateDifference.Days

            ($LocalUserProfiles | Where-Object { $_.SID -eq $Profile.SID }).ProfileAge = $DaysSinceLogon

            if ($Profile.Username -ieq $Global:VariableTable.EnrolledUser.Username) {
                $ProfileAction = "Ignore"
            } elseif ($Profile.Username -ieq $Global:VariableTable.EnrollmentUser.Username) {
                $ProfileAction = "Ignore"
            } elseif ($Profile.Username -in $ExcludedUserNames) {
                $ProfileAction = "Ignore"
            } elseif ($Profile.Username -ieq "_administrator") {
                $ProfileAction = "Ignore"
            } elseif ($Profile.Action -eq "Ignore") {
                $ProfileAction = "Ignore"
            } elseif ($null -eq $Profile.Username) {
                ##! Check this one
                Write-Log -Message "No username is available for this profile, checking if it is an orphaned profile." -Component ${CmdletName}
                [bool]$NoUsername = $true
                [bool]$NoSID = $false
                [bool]$NoPath = $false
                [bool]$NoLastLogon = $false

                if ($null -eq $Profile.SID) {
                    $NoSID = $true
                }

                if ($null -eq $Profile.Path) {
                    $NoPath = $true
                }

                if ($null -eq $Profile.LastLogon) {
                    $NoLastLogon = $true
                }

                if (($NoSID -eq $true) -and ($NoLastLogon -eq $true) -and ($NoPath -eq $false)) {
                    Write-Log -Message "Orphaned profile detected with path $($Profile.Path), an attempt will be made to remove the files" -Component ${CmdletName}
                    if ($Profile -ine "C:\Users\Administrator") {
                        $ProfileAction = "Orphan"
                    } else {
                        $ProfileAction = "Ignore"
                    }
                }
            } else {
                # Get the action to be performed
                try {
                    Write-Log -Message "Profile Username :: $($Profile.Username)" -Component ${CmdletName} -DebugMessage
                    Write-Log -Message "EnrolledUser.Username :: $($Global:VariableTable.EnrolledUser.Username)" -Component ${CmdletName} -DebugMessage
                    Write-Log -Message "Timespace :: $($DaysSinceLogon)" -Component ${CmdletName} -DebugMessage
                    Write-Log -Message "ProfileAge :: $($ProfileAge)" -Component ${CmdletName} -DebugMessage
                    Write-Log -Message "ProfileGrace :: $($ProfileGrace)" -Component ${CmdletName} -DebugMessage
                    if (($null -eq $Profile.Username) -or ($null -eq $Profile.SID) -or ($null -eq $Profile.Path) -or ($null -eq $Profile.SizeMB) -or ($null -eq $Profile.LastLogon)) {
                        $ProfileAction = "Manual"
                    } elseif ($Profile.Username -eq $Global:VariableTable.EnrolledUser.Username) {
                        $ProfileAction = "Ignore"
                    } elseif ($DaysSinceLogon -ge $ProfileAge) {
                        $ProfileAction = "Delete"
                    } elseif ($DaysSinceLogon -ge $ProfileGrace) {
                        $ProfileAction = "Clean"
                    } else {
                        $ProfileAction = "Audit"
                    }
                } catch {
                    Write-Log -Message "Error determining action for the profile $($Profile.Username)" -Component ${CmdletName} -Severity 3
                    Write-Log -Message "Profile Last Logon: $($Profile.LastLogon)" -Component ${CmdletName}
                ($LocalUserProfiles | Where-Object { $_.Username -eq $Profile.Username }).Action = "Error"
                }
            }

            if ($null -eq $Profile.Username) {
                Write-Log -Message "Adding action '$ProfileAction' to record by path for $($Profile.Path)" -Component ${CmdletName}
                        ($LocalUserProfiles | Where-Object { $_.Path -eq $Profile.Path }).Action = $ProfileAction
            } else {
                Write-Log -Message "Adding action '$ProfileAction' to record by username for $($Profile.Username)" -Component ${CmdletName}
                        ($LocalUserProfiles | Where-Object { $_.Username -eq $Profile.Username }).Action = $ProfileAction
            }

            Write-Log -Message "Profile Action :: $ProfileAction" -Component ${CmdletName} -DebugMessage
            [string]$ProfileSizeText = $($Profile.SizeMB)
            Write-Log -Message "Profile Size ::  $($Profile.SizeMB)" -Component ${CmdletName} -DebugMessage

            Write-Log -Message "Profile: $($Profile.Username), Action: $ProfileAction, Profile Last Logon: $($Profile.LastLogon), Days Since Logon: $($DaysSinceLogon), Profile Size: $ProfileSizeText" -Component ${CmdletName} -ScriptSection "Get-ProfileAction"
        }

        foreach ($LocalProfile in $LocalUserProfiles) {
            Write-Host "Attempting to add $($LocalProfile.username)"
            Update-DatabaseUserEntry -CollectedInformation $LocalProfile
        }



        if ($IsTesting -ne $True) {
            try {
                Write-Log -Message "Actioning Profiles" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                foreach ($CleanUser in ($LocalUserProfiles | Where-Object { $_.Action -eq "Clean" })) {
                    if (Test-Path -Path "$($CleanUser.Path)\Desktop") {
                        Write-Log -Message "Cleaning $($CleanUser.Path)\Desktop" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                        Get-ChildItem -Path "$($CleanUser.Path)\Desktop" -Recurse | ForEach-Object { Remove-Item $_.FullName -Recurse -Force } -ErrorAction SilentlyContinue | Out-Null
                    }
                    if (Test-Path -Path "$($CleanUser.Path)\Downloads") {
                        Write-Log -Message "Cleaning $($CleanUser.Path)\Downloads" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                        Get-ChildItem -Path "$($CleanUser.Path)\Downloads" -Recurse | ForEach-Object { Remove-Item $_.FullName -Recurse -Force } -ErrorAction SilentlyContinue | Out-Null
                    }
                    if (Test-Path -Path "$($CleanUser.Path)\AppData\Local\Temp") {
                        Write-Log -Message "Cleaning $($CleanUser.Path)\AppData\Local\Temp" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                        try {
                            Get-ChildItem -Path "$($CleanUser.Path)\AppData\Local\Temp" -Recurse | ForEach-Object { Remove-Item $_.FullName -Recurse -Force } -ErrorAction SilentlyContinue | Out-Null
                        } catch {
                        }
                    }
                    if (Test-Path -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Teams") {
                        Write-Log -Message "Cleaning $($CleanUser.Path)\AppData\Local\Microsoft\Teams" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                        Get-ChildItem -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Teams" -Recurse | ForEach-Object { Remove-Item $_.FullName -Recurse -Force } -ErrorAction SilentlyContinue | Out-Null
                    }
                    if (Test-Path -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Terminal Server Client\Cache") {
                        Write-Log -Message "Cleaning $($CleanUser.Path)\AppData\Local\Microsoft\Terminal Server Client\Cache" -Component ${CmdletName} -ScriptSection "Action-Profiles"
                        Get-ChildItem -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Terminal Server Client\Cache" -Recurse | ForEach-Object { Remove-Item $_.FullName -Recurse -Force } -ErrorAction SilentlyContinue | Out-Null
                    }
                    Write-Log -Message "Profile for $($CleanUser.username) cleared" -Component ${CmdletName} -ScriptSection "Clear-Profile"

                    Write-Log -Message "Checking $($CleanUser.Path) for OST files" -Component ${CmdletName}
                    if (Test-Path -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Outlook") {
                        Write-Log -Message "OST found in $($CleanUser.Path), removing file" -Component ${CmdletName}
                        $OSTs = Get-Item -Path "$($CleanUser.Path)\AppData\Local\Microsoft\Outlook\*" -Filter "*.ost"
                        foreach ($OST in $OSTs) {
                            Remove-Item -Path "$($OST.FullName)" -Force
                        }
                    }
                }
                $AllUserProfilesCIM = Get-CimInstance -ClassName Win32_UserProfile -Filter "Special='False'"

                foreach ($DeleteUser in ($LocalUserProfiles | Where-Object { $_.Action -eq "Delete" })) {
                    try {
                        if ($AllUserProfilesCIM.LocalPath -contains $DeleteUser.Path) {
                            if ($null -eq $DeleteUser.Username) {
                                Write-Log -Message "Removing orphaned profile for $($DeleteUser.Path)" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                            } else {
                                Write-Log -Message "Removing profile for $($DeleteUser.Username)" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                            }
                            Write-Log -Message "DeleteUser :: Username: $($DeleteUser.username), Path: $($DeleteUser.Path)"
                            Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $DeleteUser.Username } | Remove-CimInstance
                        } else {
                            Write-Log -Message "Profile does not exist in CIM, continuing to remove files" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                        }
                    } catch {
                        Write-Log -Message "Error removing profile for $($DeleteUser.username) in WMI." -Component ${CmdletName} -ScriptSection "Delete-Profile"
                    }
                    try {
                        if (Test-Path -Path $DeleteUser.Path) {
                            Remove-Folder -Path $DeleteUser.Path
                        }
                    } catch {
                        Write-Log -Message "Error removing profile for $($DeleteUser.username) in Folder removal." -Component ${CmdletName} -ScriptSection "Delete-Profile"
                    }

                    Write-Log -Message "Profile for $($DeleteUser.username) deleted" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                }
            } catch {
                Write-Log -Message "Error removing profile for $($DeleteUser.username)." -Component ${CmdletName} -ScriptSection "Delete-Profile"
            }
        }

        foreach ($OrphanUser in ($LocalUserProfiles | Where-Object { $_.Action -eq "Orphan" })) {
            try {
                Write-Log -Message "Removing orphaned profile for $($OrphanUser.Path)" -Component ${CmdletName} -ScriptSection "Delete-Profile"

                if (Test-Path -Path $OrphanUser.Path) {
                    Remove-Folder -Path $OrphanUser.Path
                }

                Write-Log -Message "Orphaned profile for $($OrphanUser.Path) deleted" -Component ${CmdletName} -ScriptSection "Delete-Profile"
            } catch {
                Write-Log -Message "Error removing profile for $($OrphanUser.Path)." -Component ${CmdletName} -ScriptSection "Delete-Profile"
            }
        }

        # Check that profiles have been removed, and if so remove them from the database
        Write-Log -Message "Checking local profiles again to ensure profiles have been deleted that needed to be deleted" -Component ${CmdletName} -ScriptSection "Delete-Profile"
        $TempLocalUserProfiles = Get-LocalUserProfiles

        foreach ($CheckUser in ($LocalUserProfiles | Where-Object { $_.Action -eq "Delete" })) {
            if ($CheckUser.SID -notin $TempLocalUserProfiles.SID) {
                Write-Log -Message "$($CheckUser.Username) has been removed from the device, removing the entry from the database" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                $filter = @{ "SID" = $CheckUser.SID }
                Remove-DatabaseEntry -Database $DatabaseObject -CollectionName "Users" -Filter $filter
            } else {
                Write-Log -Message "$($CheckUser.Username) has NOT been removed from the device, leaving the entry in the database" -Component ${CmdletName} -ScriptSection "Delete-Profile" -Severity 3
            }
        }

        foreach ($CheckUser in ($LocalUserProfiles | Where-Object { $_.Action -eq "Orphan" })) {
            if ($CheckUser.Path -notin $TempLocalUserProfiles.Path) {
                Write-Log -Message "$($CheckUser.Username) has been removed from the device, removing the entry from the database" -Component ${CmdletName} -ScriptSection "Delete-Profile"
                $filter = @{ "Path" = $CheckUser.Path }
                Remove-DatabaseEntry -Database $DatabaseObject -CollectionName "Users" -Filter $filter
            } else {
                Write-Log -Message "$($CheckUser.Username) has NOT been removed from the device, leaving the entry in the database" -Component ${CmdletName} -ScriptSection "Delete-Profile" -Severity 3
            }
        }

        $Global:ScriptSection = "Post Result Recording"

        $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive
        Update-DatabaseDiskSpaceEntry -Mode "ProfileCleanup" -CollectedInformation $DiskStatistics -Status "Completed"

    }

    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialize-ProfileCleanup

#region Initialise-ScriptVariables
Function Initialize-ScriptVariables {
    <#
.SYNOPSIS
Initializes script variables required for script execution.

.DESCRIPTION
This function initializes various script variables including API credentials, database details, device information, file locations, MSI options, registry key paths, scheduled tasks, and more. These variables are essential for the proper execution of the script.

.PARAMETER Agency
Specifies the agency to which the script variables belong.

.EXAMPLE
Initialize-ScriptVariables -Agency "AgencyName"

.NOTES
This function must be called before using other functions in the script to ensure that all required variables are properly initialized.
#>
    Param ([string]$Agency
    )

    Begin {
        [version]$FunctionVersion = "1.24.02.1"
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        #$Management = Get-ManagementType
        $Management = "WS1"

        [PSCustomObject]$AgencyDatabaseEntry = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Agency"

        if ($FirstRun.IsPresent) {}else {
            if ($null -eq $AgencyDatabaseEntry) {
                Write-Log -Message "Unable to retrieve basic information from the database, exiting script" -Severity 3 -Component ${CmdletName}
                Exit-Script
            }
        }

        [PSCustomObject]$EnrollmentDetailsObject = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Enrollment"

        if ($FirstRun.IsPresent) {}else {
            if ($null -eq $EnrollmentDetailsObject) {
                Write-Log -Message "Unable to retrieve enrollment information from the database, exiting script" -Severity 3 -Component ${CmdletName}
                Exit-Script
            }
        }

        [array]$TagNamesToIgnore = @("TEMP-Profile Cleanup Script",
            "DEV-Profile Cleanup")

        $UsersObject = [pscustomobject]@{
            ExcludedActiveUsers = @("SYSTEM",
                "SERVICE",
                "DWM-",
                "UMFD-",
                "ANONYMOUS LOGON",
                "TELEMETRY")
            ExcludedLocalSIDs   = @(".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20")
            ExcludedUsernames   = @("DefaultAppPool", "_Administrator")
            ExcludedDomains     = @("NT Authority")
        }
        [string] $BaseURI = $AgencyDatabaseEntry.BaseURI
        if ($Management -eq "WS1") {

        } elseif ($Management -eq "InTune") {
            $APIEndpoints = [PSCustomObject]@{
            }
        }

        $CIMNamespaces = [PSCustomObject]@{
            StoreApps   = [PSCustomObject]@{
                'Namespace' = "Root\cimv2\mdm\dmmap"
                'ClassName' = "MDM_Enterprisemodernappmanagement_appmanagement01"
                Command     = "Get-CimInstance"
            }
            StoreUpdate = [PSCustomObject]@{
                'MethodName' = "updatescanmethod"
                Command      = "Invoke-CimMethod"
            }
            LogicalDisk = [PSCustomObject]@{
                ClassName = "Win32_LogicalDisk"
                Command   = "Get-CimInstance"
            }
        }

        # Registry Key Locations
        [string]$TempCompany = "HKLM:\SOFTWARE\Company"
        [string]$TempBaseMicrosoftRegKey = "HKLM:\SOFTWARE\Microsoft"
        [String]$TempBaseNotifications = "$TempBaseMicrosoftRegKey\Windows\CurrentVersion\Notifications\Settings"
        $RegKeyLocationObject = [PSCustomObject]@{
            EnrollmentID              = "$TempBaseMicrosoftRegKey\Provisioning\OMADM\Accounts"
            EnrollmentPath            = "$TempBaseMicrosoftRegKey\Enrollments\##EnrollmentID##"
            UninstallWow6432          = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            Uninstall                 = "$TempBaseMicrosoftRegKey\Windows\CurrentVersion\Uninstall"
            SFDAgent                  = "$TempBaseMicrosoftRegKey\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI"
            EnterpriseResourceManager = "$TempBaseMicrosoftRegKey\EnterpriseResourceManager\Tracked"
            Notifications             = [PSCustomObject]@{
                DeviceEnrollmentActivity = "$TempBaseNotifications\Windows.SystemToast.DeviceEnrollmentActivity"
            }
            Company                   = $TempCompany
            VolumeCaches              = "$TempBaseMicrosoftRegKey\Windows\CurrentVersion\Explorer\VolumeCaches"
            ProfileList               = "$TempBaseMicrosoftRegKey\Windows NT\CurrentVersion\ProfileList"
            HealthCheck               = "$TempCompany\HealthCheck"
            DeviceInformation         = "$TempCompany\DeviceInformation"
        }

        # Encryption Key Path
        if ($Encrypt -eq $true) {
            #TODO This needs to be tested
            if ($InvokingScriptFileName -like "$scriptDirectory*") {
                $EncryptionKeyPath = "$($InvokingScriptFileName.Replace("ps1","key"))"
            } else {
                $EncryptionKeyPath = "$scriptDirectory\$($InvokingScriptFileName.Replace("ps1","key"))"
            }

            if (Test-Path -Path $EncryptionKeyPath) {
                $EncryptionKey = Get-Content -Path $EncryptionKeyPath
                $AsPlainText = $false
            } else {
                Write-Log -Message "Encryption has been selected however no encryption key could be found. Proceeding with no encryption" -Severity 2 -Component ${CmdletName}
                $EncryptionKey = "No Key"
                $AsPlainText = $true
            }
        } else {
            $EncryptionKey = "No Key"
            $AsPlainText = $true
        }

        if ($AsPlainText -eq $true) {
            $WS1Credential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.APIUserName
                Password = $AgencyDatabaseEntry.APIPassword | ConvertTo-SecureString -AsPlainText -Force
            }

            $ReadOnlyCredential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.ReadOnlyUsername
                Password = $AgencyDatabaseEntry.ReadOnlyPassword | ConvertTo-SecureString -AsPlainText -Force
            }

            $WriteCredential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.WriteUsername
                Password = $AgencyDatabaseEntry.WritePassword | ConvertTo-SecureString -AsPlainText -Force
            }

        } else {
            #TODO This needs to be tested
            $WS1Credential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.APIUserName
                Password = $AgencyDatabaseEntry.APIPassword | ConvertTo-SecureString -Key $EncryptionKey
            }

            $ReadOnlyCredential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.ReadOnlyUsername
                Password = $AgencyDatabaseEntry.ReadOnlyPassword | ConvertTo-SecureString -Key $EncryptionKey
            }

            $WriteCredential = [PSCustomObject]@{
                Username = $AgencyDatabaseEntry.WriteUsername
                Password = $AgencyDatabaseEntry.WritePassword | ConvertTo-SecureString -Key $EncryptionKey
            }

            [securestring]$securestring = ConvertTo-SecureString $AgencyDatabaseEntry.APIPassword -Key $EncryptionKey
            [pscredential]$WS1Credential = New-Object System.Management.Automation.PsCredential($APIUserName, $securestring)

            [securestring]$readsecStringPassword = ConvertTo-SecureString $AgencyDatabaseEntry.ReadOnlyPassword -Key $EncryptionKey
            [pscredential]$ReadOnlyCredential = New-Object System.Management.Automation.PSCredential ($ReadOnlyUsername, $readsecStringPassword)

            [securestring]$writesecStringPassword = ConvertTo-SecureString $AgencyDatabaseEntry.WritePassword -Key $EncryptionKey
            [pscredential]$WriteCredential = New-Object System.Management.Automation.PSCredential ($WriteUsername, $writesecStringPassword)
        }

        [string]$KillSwitchTag = "MGMT-Health Check Disable"

        $CompanyScheduledTasks = @()
        Get-ScheduledTask -TaskPath "\Company\" -ErrorAction SilentlyContinue | ForEach-Object { $CompanyScheduledTasks += "$($_.Taskpath)$($_.Taskname)" }

        $TempActiveUser = Get-ActiveUser

        if (($null -eq $TempActiveUser) -or ((($TempActiveUser | Where-Object { $_.IsCurrentSession -eq $true }).Username.Count -eq 0) -AND (($TempActiveUser | Where-Object { $_.IsCurrentSession -eq $false }).Username.Count -gt 0))) {
            $TempActiveUser = Get-ActiveUser -SearchMode Query
        }

        if ($TempActiveUser.Domain -eq "") {
            $tempUserInformation = Get-UserName -SID $TempActiveUser.SID -Domain
            $TempActiveUser.Domain = $tempUserInformation.DomainName
        }

        $DeviceSerial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        if ($DeviceSerial -like "* *") {
            $DeviceSerial = $DeviceSerial.Replace(" ", "+")
        }

        # Retrieve information from the database
        $TempDeviceRecord = Get-DatabaseEntry -Database $databaseObject -CollectionName "Device"

        if ($Null -eq $TempDeviceRecord) {
            Write-Log -Message "The database has not been populated with default information yet, adding in information" -Component ${CmdletName}

            $DeviceRecord = [pscustomobject]@{
                DeviceID        = ""
                SerialNumber    = $DeviceSerial
                DeviceUUID      = ""
                OGID            = ""
                EnrollmentState = ""
                EnrollmentDate  = ""
                LastCheck       = $TodayString
            }

            Update-DatabaseDeviceEntry -CollectedInformation $DeviceRecord

        } else {
            $DeviceRecord = $TempDeviceRecord
        }

        if ($Management -eq "WS1") {
            # Registry Key Locations
            $RegKeyLocationObject | Add-Member -MemberType NoteProperty -Name "AirWatchMDMRegPath" -Value "HKLM:\SOFTWARE\AirWatchMDM"
            $RegKeyLocationObject | Add-Member -MemberType NoteProperty -Name "AirWatchRegPath" -Value "HKLM:\SOFTWARE\Airwatch"
            $RegKeyLocationObject.Notifications | Add-Member -MemberType NoteProperty -Name "WorkspaceONEIntelligentHub" -Value "$TempBaseNotifications\Workspace ONE Intelligent Hub"
            $RegKeyLocationObject.Notifications | Add-Member -MemberType NoteProperty -Name "windowsprotectionagent" -Value "$TempBaseNotifications\com.airwatch.windowsprotectionagent"
            $RegKeyLocationObject.Notifications | Add-Member -MemberType NoteProperty -Name "AirWatchLLC" -Value "$TempBaseNotifications\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App"

            # Scheduled Tasks
            $VMWareScheduledTasks = @()
            Get-ScheduledTask -TaskPath "\VMWare\AirWatch\" -ErrorAction SilentlyContinue | ForEach-Object { $VMWareScheduledTasks += "$($_.Taskpath)$($_.Taskname)" }
            Get-ScheduledTask -TaskPath "\VMWare\SfdAgent\" -ErrorAction SilentlyContinue | ForEach-Object { $VMWareScheduledTasks += "$($_.Taskpath)$($_.Taskname)" }
            Get-ScheduledTask -TaskPath "\AirWatch MDM\" -ErrorAction SilentlyContinue | ForEach-Object { $VMWareScheduledTasks += "$($_.Taskpath)$($_.Taskname)" }

            # API Headers
            if ($AsPlainText -eq $true) {
                $tempHeaders = [PSCustomObject]@{
                    Header1 = New-WS1APIHeader -APIUserName $WS1Credential.Username -APIPassword $WS1Credential.Password -APITenantKey $AgencyDatabaseEntry.APITenantKey
                    Header2 = New-WS1APIHeader -APIUserName $WS1Credential.Username -APIPassword $WS1Credential.Password -APITenantKey $AgencyDatabaseEntry.APITenantKey -APIVersion 2
                    Header3 = New-WS1APIHeader -APIUserName $WS1Credential.Username -APIPassword $WS1Credential.Password -APITenantKey $AgencyDatabaseEntry.APITenantKey -APIVersion 3
                    Header4 = New-WS1APIHeader -APIUserName $WS1Credential.Username -APIPassword $WS1Credential.Password -APITenantKey $AgencyDatabaseEntry.APITenantKey -APIVersion 4
                }
            }

            # API Endpoints
            $APIEndpoints = [PSCustomObject]@{
                DeviceSearch             = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/devices/search?pagesize=##PageSize##&page=##PageNumber##&order_by=DeviceFriendlyName"
                    'APIVersion' = 1
                }
                DeviceSearchSerialNumber = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/devices?searchBy=Serialnumber&id=##SerialNumber##"
                    'APIVersion' = 1
                }
                DeviceSearchUUID         = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/devices/##UUID##"
                    'APIVersion' = 3
                }
                SetActiveUser            = [PSCustomObject]@{
                    'Method'     = "Patch"
                    'URL'        = "$($BaseURI)/API/mdm/devices/##DeviceID##/enrollmentuser/##UserID##"
                    'APIVersion' = 1
                }
                UserSearchUsername       = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/system/users/search?username=##Username##"
                    'APIVersion' = 1
                }
                UserSearch               = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/system/users/search?page=##PageNumber##&pagesize=##PageSize##"
                    'APIVersion' = 1
                }
                DeviceTags               = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/devices/##DeviceUUID##/tags"
                    'APIVersion' = 1
                }
                DeviceProfiles           = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/devices/##DeviceID##/profiles"
                    'APIVersion' = 1
                }
                AllProfiles              = [PSCustomObject]@{
                    'Method'     = "Get"
                    'URL'        = "$($BaseURI)/API/mdm/profiles/search?searchtext=*"
                    'APIVersion' = 2
                }
                InstallProfile           = [PSCustomObject]@{
                    'Method'     = "POST"
                    'URL'        = "$($BaseURI)/API/mdm/profiles/##ProfileID##/install"
                    'APIVersion' = 1
                }
                DeviceQuery              = [PSCustomObject]@{
                    'Method'     = 'POST'
                    'URL'        = "$($BaseURI)/API/mdm/devices/##DeviceID##/commands?command=DeviceQuery"
                    'APIVersion' = 1
                }
                DeleteDevice             = [PSCustomObject]@{
                    'Method'     = 'DELETE'
                    'URL'        = "$($BaseURI)/API/mdm/devices/##DeviceID##"
                    'APIVersion' = 1
                }
                MoveOG                   = [PSCustomObject]@{
                    'Method'     = 'PUT'
                    'URL'        = "$($BaseURI)/API/mdm/mdm/devices/##DeviceID##/commands/changeorganizationgroup/##OGID##"
                    'APIVersion' = 1
                }
            }
        } elseif ($Management -eq "InTune") {
            $tempHeaders = [PSCustomObject]@{}
        }

        # Create Return Objects

        $APIObject = [PSCustomObject]@{
            BaseURI          = $AgencyDatabaseEntry.BaseURI
            Username         = $AgencyDatabaseEntry.APIUserName
            Password         = $AgencyDatabaseEntry.APIPassword
            CredentialObject = ""
            TenantKey        = $AgencyDatabaseEntry.APITenantKey
            EndPoints        = $APIEndpoints
            Header           = $tempHeaders
            PageSize         = $DefaultAPIPageSize # Page size used for API calls
        }

        $ApplicationDetailsObject = [PSCustomObject]@{
            DisplayName = "Workspace ONE Intelligent Hub Installer" # Display name for the WS1 applicaiton in Add Remove Programs
            ProductID   = "" # Product ID for the WS1 agent in Add Remove Programs
        }

        $tempDatabaseObject = [PSCustomObject]@{
            DataSource               = $AgencyDatabaseEntry.DataSource                                              # SQL server name
            ApplicationDatabase      = $AgencyDatabaseEntry.ApplicationDatabase                                     # Database name for the application database
            WS1Database              = $AgencyDatabaseEntry.WS1Database                                             # Database name for Workspace ONE
            ReadOnlyUsername         = $AgencyDatabaseEntry.ReadOnlyUsername                                        # Username for read only access to databases
            ReadOnlyPassword         = $AgencyDatabaseEntry.ReadOnlyPassword                                        # Password for read only access to databases
            ReadOnlyCredentialObject = $ReadOnlyCredential                                      # Credential object for read only access to databases
            WriteUsername            = $AgencyDatabaseEntry.WriteUsername                                           # Username for write access to application database
            WritePassword            = $AgencyDatabaseEntry.WritePassword                                           # Password for write access to application database
            WriteCredentialObject    = $WriteCredential                                         # Credential object for write access to application database
        }

        $DeviceObject = [PSCustomObject]@{
            Name            = $ENV:COMPUTERNAME                                                 # Device name
            SerialNumber    = $DeviceSerial                                                     # Device serial number
            DeviceID        = $DeviceRecord.DeviceID                                            # WS1 device ID
            DeviceUUID      = $DeviceRecord.DeviceUUID                                          # WS1 device UUID
            EnrollmentState = $DeviceRecord.EnrollmentState                                     # Enrollment state
            OGID            = $DeviceRecord.OGID                                                # WS1 OG ID
            Management      = $Management                                                       # What system is managing the device
            EnrollmentDate  = $DeviceRecord.EnrollmentDate                                      # Enrollment date
            Tags            = ""                                                                # List of tags associated with the device
            Profiles        = ""                                                                # A list of all profiles associated with the device
            Applications    = ""                                                                # A list of all applications associated with the device
        }

        $UserDetailsObject = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Users"

        if ($null -ne $UserDetailsObject) {
            $tempEnrolledUserObject = $UserDetailsObject | Where-Object { $_.EnrolledUser -eq "$true" }
            $tempEnrollmentUserObject = $UserDetailsObject | Where-Object { $_.EnrollmentUser -eq "$true" }
        } else {
            $tempEnrolledUserObject = $null
            $tempEnrollmentUserObject = $null
        }

        $ActiveUserObject = [PSCustomObject]@{
            UserUPN          = $TempActiveUser.UPN
            Username         = $TempActiveUser.Username
            Domain           = $TempActiveUser.domain
            IsConsoleSession = $TempActiveUser.IsConsoleSession
            IsCurrentSession = $TempActiveUser.IsCurrentSession
            SID              = $TempActiveUser.SID
            ActiveUser       = $True
        }

        $EnrolledUserObject = [PSCustomObject]@{
            UserUPN  = $tempEnrolledUserObject.UserUPN
            Username = $tempEnrolledUserObject.Username
            UserID   = $tempEnrolledUserObject.UserID
            SID      = $tempEnrolledUserObject.SID
        }

        $EnrollmentUserObject = [PSCustomObject]@{
            UserUPN  = $tempEnrollmentUserObject.UserUPN
            Username = $tempEnrollmentUserObject.Username
            UserID   = $tempEnrollmentUserObject.UserID
            SID      = $tempEnrollmentUserObject.SID
        }


        Update-DatabaseUserEntry -CollectedInformation $ActiveUserObject
        if ($null -ne $EnrolledUserObject.Username) { Update-DatabaseUserEntry -CollectedInformation $EnrolledUserObject }
        if ($null -ne $EnrolledUserObject.Username) { Update-DatabaseUserEntry -CollectedInformation $EnrolledUserObject }

        $FileLocationsObject = [PSCustomObject]@{
            SCCMCache      = "$ENV:WinDir\CCMCache"
            WS1Install     = "${ENV:ProgramFiles(x86)}\Airwatch\AgentUI"
            WS1Update      = "${ENV:ProgramFiles(x86)}\Airwatch\AgentUI\Update"
            WS1Updater     = "${ENV:ProgramFiles(x86)}\Airwatch\AgentUI\AW.WinPC.Updater.exe"
            WS1Logs        = "$ENV:ProgramData\Airwatch\UnifiedAgent\Logs"
            WS1SupportLogs = "$ENV:ProgramData\AirWatchMDM\Support"
            WS1Cache       = "$ENV:ProgramData\AirWatchMDM\AppDeploymentCache"
        }

        $MSIOptionsObject = [PSCustomObject]@{
            DisplayMode           = "Silent"
            InstallParams         = "REBOOT=ReallySuppress /QB!" # Install parameters for MSI installation
            InstallParamsSilent   = "REBOOT=ReallySuppress /QN" # Silent install parameters for MSI installation
            UninstallParams       = "REBOOT=ReallySuppress /QB!" # Uninstall parameters for MSI uninstallation
            UninstallParamsSilent = "REBOOT=ReallySuppress /QN"  # Silent uninstall parameters for MSI uninstallation
        }

        $ScheduledTasksObject = [PSCustomObject]@{
            VMWareTasks = $VMWareScheduledTasks
            CompanyTasks    = $CompanyScheduledTasks
        }

        $SFDAgentObject = [PSCustomObject]@{
            DisplayName = "VMware SfdAgent"
            ProducuctID = ""
        }


        $ReturnObject = [PSCustomObject]@{
            ActiveUser         = $ActiveUserObject
            Agency             = $Agency                                                    # Agency that these details belong to
            API                = $APIObject
            ApplicationDetails = $ApplicationDetailsObject
            CIMNamespaces      = $CIMNamespaces                                             # List of CIM/WMI namespaces
            DatabaseDetails    = $tempDatabaseObject
            Device             = $DeviceObject                                              # Details about the device
            EncryptionKey      = $EncryptionKey                                             # Encryption key used to decode any encrypted passwords
            EnrolledUser       = $EnrolledUserObject                                        # Details about the enrolled user
            EnrollmentDetails  = $EnrollmentDetailsObject                                   # Details about the enrollment of the device
            EnrollmentUser     = $EnrollmentUserObject                                      # Details about the enrollment user
            FileLocations      = $FileLocationsObject
            MSIOptions         = $MSIOptionsObject
            RegKeyPaths        = $RegKeyLocationObject                                      # Any registry locations to be used in the script
            ScheduledTasks     = $ScheduledTasksObject
            SFDAgent           = $SFDAgentObject
            TagsToIgnore       = $TagNamesToIgnore | Where-Object { $_ }                    # List of tags to ignore
            Killswitch         = $KillSwitchTag
            Users              = $UsersObject
        }

        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialise-ScriptVariables

#region Initialize-UserSwitch
# TODO Write doco
# ToDO finish the function
Function Initialize-UserSwitch {
    <#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE
    Initialize-UserSwitch -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        # Checks to see if the current logged on user is the enrolled and enrollment user

        # if its not, change them

        # initiate the re-run of all profiles
        $InstallProfileURL = [PSCustomObject]@{
            URL    = $Global:VariableTable.API.Endpoints.InstallProfile.URL
            Header = switch ($Global:VariableTable.API.Endpoints.InstallProfile.APIVersion) {
                1 { $Global:VariableTable.API.Header.Header1 }
                2 { $Global:VariableTable.API.Header.Header2 }
                3 { $Global:VariableTable.API.Header.Header3 }
                4 { $Global:VariableTable.API.Header.Header4 }
                Default { $Global:VariableTable.API.Header.Header1 }
            }
            Method = $Global:VariableTable.API.Endpoints.InstallProfile.Method
        }
        foreach ($Profile in $Global:VariableTable.Device.Profiles) {
            try {
                $url = $InstallProfileURL.URL.Replace("##ProfileID##", $Profile.ID.Value)
                $Body = @{
                    DeviceID = $Global:VariableTable.Device.ID
                }

                Write-Log -Message "URL: $($url.toString())" -Component ${CmdletName} -DebugMessage
                Write-Log -Message "Method: $($InstallProfileURL.Method)" -Component ${CmdletName} -DebugMessage
                $Count = 0
                do {
                    $Count++
                    try {
                        Write-Log -Message "$($url.ToString())" -Component ${CmdletName} -DebugMessage
                        $response = Invoke-RestMethod -Method $InstallProfileURL.Method -Uri $url.ToString() -Headers $InstallProfileURL.Header -Body ($Body | ConvertTo-Json) -TimeoutSec $RestMethodTimeout

                        $innerLoopEnd = $true
                        Write-Log -Message "APIs took $count attempts" -Component ${CmdletName} -DebugMessage
                    } catch {
                        Write-Log -Message "Error getting API... waiting 30 seconds and trying again" -Component ${CmdletName} -Severity 1
                        $innerLoopEnd = $false
                        Start-Sleep -Seconds 30

                    }

                    if ($Count -gt 10) {
                        Write-Log -Message "Unable to obtain a successful API call after more than 10 attempts. Exiting script and will try again" -Component ${CmdletName} -Severity 1
                        $innerLoopEnd = $True
                        throw
                    }
                } until (
                    $innerLoopEnd -eq $true
                )
                if ($null -eq $Response) {
                    Write-Log -Message "No profiles were returned for this device" -Component ${CmdletName}
                } else {
                    Write-Log -Message "$($Profile.Name) has been repushed for this device" -Component ${CmdletName}
                }
            } catch {
                Write-Log -Message "An error occured trying to repush $($Profile.Name). Exception: $($_.Exception.Message)" -Component ${CmdletName}

            }

        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialize-UserSwitch

#region New-TempFiles
Function New-TempFiles {
    <#
.SYNOPSIS
Creates a temporary file with a specified size.

.DESCRIPTION
This function generates a temporary file at the specified path. The size of the file can be defined by the user, allowing for the creation of a file for testing purposes, such as load, storage capacity testing, or other similar uses.

.PARAMETER Path
The directory path where the temporary file will be created. If the path does not exist, it will be created.

.PARAMETER Size
The size of the temporary file to be created. The size can be specified in bytes, KB, MB, or GB. For example, "10MB" or "1GB". If the size is not specified correctly, a default size of 100MB will be used.

.EXAMPLE
New-TempFiles -Path "C:\Temp" -Size "50MB"

This example creates a 50MB temporary file named TempFile.txt in the C:\Temp directory.

.NOTES
The function attempts to parse the size parameter to support different units of measurement. If the size parameter is not provided or cannot be parsed, it defaults to creating a 100MB file.

#>
    Param ([string]$Path,
        [string]$size
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $FilePath = "$Path\TempFile.txt"
        try {
            if ($size.Substring($size.length - 2, 2) -notmatch "^\d+$") {
                $Amount = $size.Substring(0, $size.length - 2)
                $Unit = $size.Substring($size.length - 2, 2)
                $Size = Convert-Size -From $Unit -To "Bytes" -Value $Amount
            }
        } catch {
            $size = 104857600
            Write-Log -Message "Unable to determine the size required. Creating file with size $size" -Component ${CmdletName}
        }

        $FileExists = Test-Path $Path
        if (!$FileExists) {
            try {
                New-Item -Path "$Path" -ItemType Directory | Out-Null
            } catch {    }

        }
        $out = New-Object byte[] $size; (New-Object Random).NextBytes($out); [IO.File]::WriteAllBytes("$FilePath", $out)

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion New-TempFiles

#region New-WS1APIHeader
Function New-WS1APIHeader {
    <#
.SYNOPSIS
Creates authentication headers for Workspace ONE API requests.

.DESCRIPTION
This function generates the necessary authentication headers required for making API requests to Workspace ONE. It accepts credentials and tenant information, and optionally the API version, then constructs a standard HTTP header including the Authorization, Accept, and Content-Type fields.

.PARAMETER APIUserName
The API user's username required for authentication.

.PARAMETER APIPassword
The API user's password required for authentication. This parameter is of type SecureString to enhance security.

.PARAMETER APITenantKey
The unique tenant key provided by Workspace ONE for API access.

.PARAMETER DefaultUseJSON
The default media type for Accept and Content-Type headers. Defaults to "application/json". If an API version is specified, it appends ";version=APIVersion" to the media type.

.PARAMETER APIVersion
(Optional) The version of the API you wish to target. If specified, it modifies the Accept and Content-Type headers to request this specific version of the API.

.EXAMPLE
$securePassword = ConvertTo-SecureString "YourAPIPassword" -AsPlainText -Force
New-WS1APIHeader -APIUserName "YourAPIUsername" -APIPassword $securePassword -APITenantKey "YourTenantKey"

Generates the authentication headers required for Workspace ONE API access using the provided username, password, and tenant key.

.NOTES
Ensure that the API user credentials and tenant key are correctly provided and have sufficient permissions for the intended API operations. The function outputs a hashtable suitable for use with the `-Headers` parameter in Invoke-RestMethod and Invoke-WebRequest cmdlets.

#>
    Param (
        [string]$APIUserName,
        [securestring]$APIPassword,
        [string]$APITenantKey,
        [string]$DefaultUseJSON = "application/json",
        [int]$APIVersion
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        #Secure password
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIPassword)
        $combined = $APIUserName + ":" + [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
        $encodedString = [Convert]::ToBase64String($encoding)
        $encryptedAuthString = "Basic " + $encodedString

        if ($APIVersion) {
            $DefaultUseJSON = "application/json;version=$APIVersion"
        } else {
            $DefaultUseJSON = "application/json"
        }
        $headers = @{
            "Authorization"  = $encryptedAuthString
            "aw-tenant-code" = $APITenantKey
            "Accept"         = $DefaultUseJSON
            "Content-Type"   = $DefaultUseJSON
        }

        Write-Output $headers

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion New-WS1APIHeader

#region Remove-Folder
Function Remove-Folder {
    <#
.SYNOPSIS
	Remove folder and files if they exist.
.DESCRIPTION
	Remove folder and all files with or without recursion in a given path.
.PARAMETER Path
	Path to the folder to remove.
.PARAMETER DisableRecursion
	Disables recursion while deleting.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Remove-Folder -Path "$envWinDir\Downloaded Program Files"
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [switch]$DisableRecursion,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [boolean]$ContinueOnError = $true
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        If (Test-Path -LiteralPath $Path -PathType 'Container') {
            Try {
                If ($DisableRecursion) {
                    Write-Log -Message "Delete folder [$path] without recursion..." -Component ${CmdletName}
                    Remove-Item -LiteralPath $Path -Force -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFolder'
                } else {
                    Write-Log -Message "Delete folder [$path] recursively..." -Component ${CmdletName}
                    Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFolder'
                }

                If ($ErrorRemoveFolder) {
                    Write-Log -Message "The following error(s) took place while deleting folder(s) and file(s) recursively from path [$path]. `n$(Resolve-Error -ErrorRecord $ErrorRemoveFolder)" -Severity 2 -Component ${CmdletName}
                }
            } Catch {
                Write-Log -Message "Failed to delete folder(s) and file(s) recursively from path [$path]. `n$(Resolve-Error)" -Severity 3 -Component ${CmdletName}
                If (-not $ContinueOnError) {
                    Throw "Failed to delete folder(s) and file(s) recursively from path [$path]: $($_.Exception.Message)"
                }
            }
        } Else {
            Write-Log -Message "Folder [$Path] does not exists..." -Component ${CmdletName}
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Remove-Folder

#region Resolve-Error
Function Resolve-Error {
    <#
.SYNOPSIS
	Enumerate error record details.
.DESCRIPTION
	Enumerate an error record, or a collection of error record, properties. By default, the details for the last error will be enumerated.
.PARAMETER ErrorRecord
	The error record to resolve. The default error record is the latest one: $global:Error[0]. This parameter will also accept an array of error records.
.PARAMETER Property
	The list of properties to display from the error record. Use "*" to display all properties.
	Default list of error properties is: Message, FullyQualifiedErrorId, ScriptStackTrace, PositionMessage, InnerException
.PARAMETER GetErrorRecord
	Get error record details as represented by $_.
.PARAMETER GetErrorInvocation
	Get error record invocation information as represented by $_.InvocationInfo.
.PARAMETER GetErrorException
	Get error record exception details as represented by $_.Exception.
.PARAMETER GetErrorInnerException
	Get error record inner exception details as represented by $_.Exception.InnerException. Will retrieve all inner exceptions if there is more than one.
.EXAMPLE
	Resolve-Error
.EXAMPLE
	Resolve-Error -Property *
.EXAMPLE
	Resolve-Error -Property InnerException
.EXAMPLE
	Resolve-Error -GetErrorInvocation:$false
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [string[]]$Property = ('Message', 'InnerException', 'FullyQualifiedErrorId', 'ScriptStackTrace', 'PositionMessage'),
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$GetErrorRecord = $true,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$GetErrorInvocation = $true,
        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$GetErrorException = $true,
        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$GetErrorInnerException = $true
    )

    Begin {
        ## If function was called without specifying an error record, then choose the latest error that occured
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                #Write-Warning -Message "The `$Error collection is empty"
                Return
            } Else {
                [array]$ErrorRecord = $global:Error[0]
            }
        }

        ## Allows selecting and filtering the properties on the error object if they exist
        [scriptblock]$SelectProperty = {
            Param (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                $InputObject,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                [string[]]$Property
            )

            [string[]]$ObjectProperty = ($InputObject | Get-Member -MemberType '*Property').Name
            ForEach ($Prop in $Property) {
                If ($Prop -eq '*') {
                    [string[]]$PropertySelection = $ObjectProperty
                    Break
                } ElseIf ($ObjectProperty -contains $Prop) {
                    [string[]]$PropertySelection += $Prop
                }
            }
            Write-Output -InputObject $PropertySelection
        }

        #  Initialize variables to avoid error if 'Set-StrictMode' is set
        $LogErrorRecordMsg = $null
        $LogErrorInvocationMsg = $null
        $LogErrorExceptionMsg = $null
        $LogErrorMessageTmp = $null
        $LogInnerMessage = $null
    }
    Process {
        If (-not $ErrorRecord) { Return }
        ForEach ($ErrRecord in $ErrorRecord) {
            ## Capture Error Record
            If ($GetErrorRecord) {
                [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord -Property $Property
                $LogErrorRecordMsg = $ErrRecord.$SelectedProperties
            }

            ## Error Invocation Information
            If ($GetErrorInvocation) {
                If ($ErrRecord.InvocationInfo) {
                    [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.InvocationInfo -Property $Property
                    $LogErrorInvocationMsg = $ErrRecord.InvocationInfo.$SelectedProperties
                }
            }

            ## Capture Error Exception
            If ($GetErrorException) {
                If ($ErrRecord.Exception) {
                    [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.Exception -Property $Property
                    $LogErrorExceptionMsg = $ErrRecord.Exception.$SelectedProperties
                }
            }

            ## Display properties in the correct order
            If ($Property -eq '*') {
                #  If all properties were chosen for display, then arrange them in the order the error object displays them by default.
                If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
                If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
                If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
            } Else {
                #  Display selected properties in our custom order
                If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
                If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
                If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
            }

            If ($LogErrorMessageTmp) {
                $LogErrorMessage = 'Error Record:'
                $LogErrorMessage += "`n-------------"
                $LogErrorMsg = $LogErrorMessageTmp | Format-List | Out-String
                $LogErrorMessage += $LogErrorMsg
            }

            ## Capture Error Inner Exception(s)
            If ($GetErrorInnerException) {
                If ($ErrRecord.Exception -and $ErrRecord.Exception.InnerException) {
                    $LogInnerMessage = 'Error Inner Exception(s):'
                    $LogInnerMessage += "`n-------------------------"

                    $ErrorInnerException = $ErrRecord.Exception.InnerException
                    $Count = 0

                    While ($ErrorInnerException) {
                        [string]$InnerExceptionSeperator = '~' * 40

                        [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrorInnerException -Property $Property
                        $LogErrorInnerExceptionMsg = $ErrorInnerException.$SelectedProperties | Format-List | Out-String

                        If ($Count -gt 0) { $LogInnerMessage += $InnerExceptionSeperator }
                        $LogInnerMessage += $LogErrorInnerExceptionMsg

                        $Count++
                        $ErrorInnerException = $ErrorInnerException.InnerException
                    }
                }
            }

            If ($LogErrorMessage) { $Output = $LogErrorMessage }
            If ($LogInnerMessage) { $Output += $LogInnerMessage }

            Write-Output -InputObject $Output

            If (Test-Path -LiteralPath 'variable:Output') { Clear-Variable -Name 'Output' }
            If (Test-Path -LiteralPath 'variable:LogErrorMessage') { Clear-Variable -Name 'LogErrorMessage' }
            If (Test-Path -LiteralPath 'variable:LogInnerMessage') { Clear-Variable -Name 'LogInnerMessage' }
            If (Test-Path -LiteralPath 'variable:LogErrorMessageTmp') { Clear-Variable -Name 'LogErrorMessageTmp' }
        }
    }
    End {
    }
}
#endregion Resolve-Error

#region Set-WS1APIPolicy
function Set-WS1APIPolicy {
    <#
.SYNOPSIS
    Configures the API policy for Workspace ONE PowerShell functions.

.DESCRIPTION
    The Set-WS1APIPolicy function configures the API policy for Workspace ONE PowerShell functions.
    It adds a type definition for the TrustAllCertsPolicy class, allowing the use of a custom  certificate policy that accepts all certificates. It sets the security protocol to Tls12 and  assigns the custom certificate policy to the ServicePointManager, enabling connections to APIs with self-signed or untrusted certificates.

.EXAMPLE
    Set-WS1APIPolicy
    Configures the API policy for Workspace ONE PowerShell functions.

#>
    Param ()

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if (-not ("TrustAllCertsPolicy" -as [type])) {
            Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
    return true;
}
    }
"@
            $AllProtocols = [System.Net.SecurityProtocolType]::Tls12
            [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Set-WS1APIPolicy

#region Update-ADSite
Function Update-ADSite {
    <#
.SYNOPSIS
Updates the local registry with Active Directory (AD) site information.

.DESCRIPTION
This function checks the current AD site of the machine and updates the local registry with the AD site name and the current date. It is useful for tracking the AD site association of machines, especially in environments where machines might move between sites.

.EXAMPLE
Update-ADSite
Executes the function to retrieve the current AD site information and updates the local registry with these details.

.NOTES
Ensure that the AD PowerShell module is available and the executing user has adequate permissions to read AD site information and write to the local registry.

This function uses a global variable, `$Global:VariableTable.RegKeyPaths.Company`, to determine the registry path for storing AD site information. Ensure this variable is set before calling the function.

The function also relies on the `Get-ADSite`, `Convert-CustomVariableSafeString`, and `Write-Log` cmdlets, which should be available in the executing environment.
#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Write-Log -Message "Checking AD Site" -Component ${CmdletName}
        $ADSite = Get-ADSite
        if ($ADSite -ne "Error") {

            $RegistryPath = "$($Global:VariableTable.RegKeyPaths.Company)\ADSite"
            # Create the key if it does not exist
            If (-NOT (Test-Path $RegistryPath)) {
                New-Item -Path $RegistryPath -Force | Out-Null
            }

            New-ItemProperty -Path $RegistryPath -Name "ADSiteString" -Value $ADSite -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $RegistryPath -Name "ADSiteDate" -Value (Convert-CustomVariableSafeString -OriginalString "$TodayString" -ToSafe) -PropertyType String -Force | Out-Null

        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-ADSite

#region Update-BitLockerKey
Function Update-BitLockerKey {
    <#
.SYNOPSIS
Updates the BitLocker recovery key for the system drive.

.DESCRIPTION
This function updates the BitLocker recovery key for the system drive by backing up the existing recovery key protector. It retrieves the BitLocker volume associated with the system drive and then backs up the recovery key protector for that volume.

.EXAMPLE
Update-BitLockerKey

.NOTES
This function assumes that BitLocker is enabled on the system drive and that the recovery password is used as the key protector type. It backs up the existing recovery key protector to ensure recovery options are available in case of emergencies.
#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        try {
            $BLV = Get-BitLockerVolume -MountPoint "$env:systemdrive"
            Backup-BitLockerKeyProtector -MountPoint "$env:systemdrive" -KeyProtectorId $($blv.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).KeyProtectorId
        } catch {
            Write-Log -Message "An error occured" -Severity 3 -Component ${CmdletName}
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-BitLockerKey

#region Update-LatestVersion
# TODO Write the function
Function Update-LatestVersion {
    <#
.SYNOPSIS
    Checks that the latest version of the script is running, if its not it will update and relaunch
.EXAMPLE
    Update-LatestVersion
.NOTES
    Requires access to DFS share or GitHub, I dont know, I haven't worked out how to do it yet
#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        # Remember to check for a reg key to say dont update before you run

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-LatestVersion
#region Write-FunctionHeaderOrFooter
Function Write-FunctionHeaderOrFooter {
    <#
.SYNOPSIS
    Write the function header or footer to the log upon first entering or exiting a function.
.DESCRIPTION
    Write the "Function Start" message, the bound parameters the function was invoked with, or the "Function End" message when entering or exiting a function.
    Messages are debug messages so will only be logged if LogDebugMessage option is enabled in XML config file.
.PARAMETER CmdletName
    The name of the function this function is invoked from.
.PARAMETER CmdletBoundParameters
    The bound parameters of the function this function is invoked from.
.PARAMETER Header
    Write the function header.
.PARAMETER Footer
    Write the function footer.
.EXAMPLE
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -CmdletBoundParameters $PSBoundParameters -Header
.EXAMPLE
    Write-FunctionHeaderOrFooter -CmdletName $CmdletName -Footer
.NOTES
    This is an internal script function and should typically not be called directly.
.LINK
    http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$CmdletName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Header')]
        [AllowEmptyCollection()]
        [hashtable]$CmdletBoundParameters,
        [Parameter(Mandatory = $true, ParameterSetName = 'Header')]
        [switch]$Header,
        [Parameter(Mandatory = $true, ParameterSetName = 'Footer')]
        [switch]$Footer
    )
    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
    If ($Header) {
        Write-Log -Message 'Function Start' -Component ${CmdletName} -DebugMessage

        ## Get the parameters that the calling function was invoked with
        [string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        If ($CmdletBoundParameters) {
            Write-Log -Message "Function invoked with bound parameter(s): `n$CmdletBoundParameters" -Component ${CmdletName} -DebugMessage
        } Else {
            Write-Log -Message 'Function invoked without any bound parameters.' -Component ${CmdletName} -DebugMessage
        }
    } ElseIf ($Footer) {
        Write-Log -Message 'Function End' -Component ${CmdletName} -DebugMessage
    }
}

#endregion Write-FunctionHeaderOrFooter

#region Write-Log
Function Write-Log {
    <#
.SYNOPSIS
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
.DESCRIPTION
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
.PARAMETER Message
	The message to write to the log file or output to the console.
.PARAMETER Severity
	Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
	Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
.PARAMETER Source
	The source of the message being logged.
.PARAMETER ScriptSection
	The heading for the portion of the script that is being executed. Default is: $script:installPhase.
.PARAMETER LogType
	Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.
.PARAMETER LogFileDirectory
	Set the directory where the log file will be saved.
.PARAMETER LogFileName
	Set the name of the log file.
.PARAMETER MaxLogFileSizeMB
	Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
.PARAMETER WriteHost
	Write the log message to the console.
.PARAMETER ContinueOnError
	Suppress writing log message to console on failure to write message to log file. Default is: $true.
.PARAMETER PassThru
	Return the message that was passed to the function
.PARAMETER DebugMessage
	Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
.PARAMETER LogDebugMessage
	Debug messages only get logged if this parameter is set to $true in the config XML file.
.EXAMPLE
	Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
.EXAMPLE
	Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [Alias('Text')]
        [string[]]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 3)]
        [int16]$Severity = 1,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [Alias("Component")]
        [string]$Source = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullorEmpty()]
        [string]$ScriptSection = $Global:ScriptSection,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('CMTrace', 'Legacy')]
        [string]$LogType = $LogStyle,
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileDirectory = $(If ($CompressLogs) {
                $logTempFolder
            } Else {
                $LogDir
            }),
        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileName = (Split-Path -Path $Global:InvokingScriptFileName -Leaf),
        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullorEmpty()]
        [decimal]$MaxLogFileSizeMB = $LogMaxSize,
        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullorEmpty()]
        [boolean]$WriteHost = $LogWriteToHost,
        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true,
        [Parameter(Mandatory = $false, Position = 10)]
        [switch]$PassThru = $false,
        [Parameter(Mandatory = $false, Position = 11)]
        [switch]$DebugMessage = $false,
        [Parameter(Mandatory = $false, Position = 12)]
        [boolean]$LogDebugMessage = $LogDebugMessage
    )

    Begin {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        if (!$source) {
            $source = ${CmdletName}
        }

        ## Logging Variables
        #  Log file date/time
        [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) {
            [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
        }
        [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        #  Initialize variables
        [boolean]$ExitLoggingFunction = $false
        If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) {
            $DisableLogging = $false
        }
        #  Check if the script section is defined
        [boolean]$ScriptSectionDefined = [boolean](-not [string]::IsNullOrEmpty($ScriptSection))
        #  Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            } Else {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        } Catch {
            $ScriptSource = ''
        }

        ## Create script block for generating CMTrace.exe compatible log entry
        [scriptblock]$CMTraceLogString = {
            Param (
                [string]$lMessage,
                [string]$lSource,
                [int16]$lSeverity
            )
            "<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        }

        ## Create script block for writing log entry to the console
        [scriptblock]$WriteLogLineToHost = {
            Param (
                [string]$lTextLogLine,
                [int16]$lSeverity
            )
            If ($WriteHost) {
                #  Only output using color options if running in a host which supports colors.
                If ($Host.UI.RawUI.ForegroundColor) {
                    if ($CustomColours) {
                        Switch ($lSeverity) {
                            3 {
                                Write-Host -Object $lTextLogLine -ForegroundColor $CustomColours.Foreground.Error -BackgroundColor $CustomColours.Background.Error
                            }
                            2 {
                                Write-Host -Object $lTextLogLine -ForegroundColor $CustomColours.Foreground.Warning -BackgroundColor $CustomColours.Background.Warning
                            }
                            1 {
                                Write-Host -Object $lTextLogLine -ForegroundColor $CustomColours.Foreground.Information -BackgroundColor $CustomColours.Background.Information
                            }
                        }
                    } elseif ($DebugMessage) {
                        Switch ($lSeverity) {
                            3 {
                                Write-Host -Object $lTextLogLine -ForegroundColor Magenta -BackgroundColor 'Black'
                            }
                            2 {
                                Write-Host -Object $lTextLogLine -ForegroundColor Blue -BackgroundColor 'Black'
                            }
                            1 {
                                Write-Host -Object $lTextLogLine -ForegroundColor Green -BackgroundColor 'Black'
                            }
                        }
                    } else {
                        Switch ($lSeverity) {
                            3 {
                                Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black'
                            }
                            2 {
                                Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black'
                            }
                            1 {
                                Write-Host -Object $lTextLogLine
                            }
                        }
                    }
                }
                #  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
                Else {
                    Write-Output -InputObject $lTextLogLine
                }
            }
        }

        ## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
        If (($DebugMessage) -and (-not $LogDebugMessage)) {
            [boolean]$ExitLoggingFunction = $true; Return
        }
        ## Exit function if logging to file is disabled and logging to console host is disabled
        If (($DisableLogging) -and (-not $WriteHost)) {
            [boolean]$ExitLoggingFunction = $true; Return
        }
        ## Exit Begin block if logging is disabled
        If ($DisableLogging) {
            Return
        }
        ## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
        If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) {
            [boolean]$ExitLoggingFunction = $true; Return
        }

        ## Create the directory where the log file will be saved
        If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
            Try {
                $null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
            } Catch {
                [boolean]$ExitLoggingFunction = $true
                #  If error creating directory, write message to console
                If (-not $ContinueOnError) {
                    Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                }
                Return
            }
        }

        ## Assemble the fully qualified path to the log file
        $LogFileExtension = $LogFileName.Substring(($LogFileName.Length - 4))

        if ($LogFileExtension -ne '.log') {
            if ($LogFileExtension.Substring(0, 1) -eq ".") {
                $LogFileName = $LogFileName.Replace($LogFileExtension, ".log")
            } else {
                $LogFileName = "$LogFileName.log"
            }
        }

        [string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
    }
    Process {
        ## Exit function if logging is disabled
        If ($ExitLoggingFunction) {
            Return
        }

        ForEach ($Msg in $Message) {
            ## If the message is not $null or empty, create the log entry for the different logging methods
            [string]$CMTraceMsg = ''
            [string]$ConsoleLogLine = ''
            [string]$LegacyTextLogLine = ''
            If ($Msg) {
                #  Create the CMTrace log message
                If ($ScriptSectionDefined) {
                    [string]$CMTraceMsg = "[$ScriptSection] :: $Msg"
                } else {
                    [string]$CMTraceMsg = "[] :: $Msg"
                }

                #  Create a Console and Legacy "text" log entry
                [string]$LegacyMsg = "[$LogDate $LogTime]"
                If ($ScriptSectionDefined) {
                    [string]$LegacyMsg += " [$ScriptSection]"
                }
                If ($Source) {
                    [string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
                    Switch ($Severity) {
                        3 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg"
                        }
                        2 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg"
                        }
                        1 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg"
                        }
                    }
                } Else {
                    [string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
                    Switch ($Severity) {
                        3 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg"
                        }
                        2 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg"
                        }
                        1 {
                            [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg"
                        }
                    }
                }
            }

            ## Execute script block to create the CMTrace.exe compatible log entry
            [string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity

            ## Choose which log type to write to file
            If ($LogType -ieq 'CMTrace') {
                [string]$LogLine = $CMTraceLogLine
            } Else {
                [string]$LogLine = $LegacyTextLogLine
            }

            ## Write the log entry to the log file if logging is not currently disabled
            If (-not $DisableLogging) {
                Try {
                    $LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
                } Catch {
                    If (-not $ContinueOnError) {
                        Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                    }
                }
            }

            ## Execute script block to write the log entry to the console if $WriteHost is $true
            & $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
        }
    }
    End {
        ## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
        Try {
            If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
                [IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
                [decimal]$LogFileSizeMB = $LogFile.Length / 1MB
                If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
                    ## Change the file extension to "lo_"
                    [string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
                    [hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }

                    ## Log message about archiving the log file
                    $ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
                    Write-Log -Message $ArchiveLogMessage @ArchiveLogParams

                    ## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
                    Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'

                    ## Start new log file and Log message about archiving the old log file
                    $NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
                    Write-Log -Message $NewLogMessage @ArchiveLogParams
                }
            }
        } Catch {
            ## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
        } Finally {
            If ($PassThru) {
                Write-Output -InputObject $Message
            }
        }
    }
}
#endregion Write-Log

#region Write-ScriptHeaderOrFooter
Function Write-ScriptHeaderOrFooter {
    <#
.SYNOPSIS
    Writes the script header or footer to the log, providing information about the script execution.

.DESCRIPTION
    The Write-ScriptHeaderOrFooter function is used to log script information at the beginning or end of its execution.
    It logs a script separator line, marks the start or end of the script, and provides details such as the script name,
    version, and bound parameters.

.PARAMETER CmdletBoundParameters
    Specifies the hashtable containing the bound parameters passed to the calling function.
    This parameter is used when the function is called to write the script header.

.PARAMETER Header
    Switch parameter to indicate that the script header should be written to the log.

.PARAMETER Footer
    Switch parameter to indicate that the script footer should be written to the log.

.EXAMPLE
    Write-ScriptHeaderOrFooter -CmdletBoundParameters $PSBoundParameters -Header
    Logs the script header, including the script separator, start marker, bound parameters, script name, and version.

.NOTES
    Author          : Aaron Whittaker
    Version         : 1.0.0

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Header')]
        [AllowEmptyCollection()]
        [hashtable]$CmdletBoundParameters,
        [Parameter(Mandatory = $true, ParameterSetName = 'Header')]
        [switch]$Header,
        [Parameter(Mandatory = $true, ParameterSetName = 'Footer')]
        [switch]$Footer
    )

    [string] ${CmdletName} = $MyInvocation.MyCommand.Name
    $scriptSeparator = '*' * 79
    If ($Header) {
        Write-Log -Message ($scriptSeparator, $scriptSeparator) -Component ${CmdletName}
        Write-Log -Message 'Script Start' -Component ${CmdletName}

        ## Get the parameters that the calling function was invoked with
        [string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        If ($CmdletBoundParameters) {
            Write-Log -Message "Script invoked with bound parameter(s): `n$CmdletBoundParameters" -Component ${CmdletName} -DebugMessage
        } Else {
            Write-Log -Message 'Script invoked without any bound parameters.' -Component ${CmdletName} -DebugMessage
        }

        Write-Log -Message "File name: $Global:InvokingScriptFileName" -Component ${CmdletName}
        Write-Log -Message "File version: $ScriptVersion" -Component ${CmdletName}
        Write-Log -Message $scriptSeparator -Component ${CmdletName}
    } ElseIf ($Footer) {
        $Global:ScriptSection = "Finalisation"
        Write-Log -Message $scriptSeparator -Component ${CmdletName}
        Write-Log -Message 'Script End' -Component ${CmdletName}
        Write-Log -Message $scriptSeparator -Component ${CmdletName}
    }
}
#endregion Write-ScriptHeaderOrFooter

#region Update-DatabaseDeviceEntry
Function Update-DatabaseDeviceEntry {
    <#
.SYNOPSIS
Updates or creates a device entry in a specified database based on collected information.

.DESCRIPTION
This function updates an existing device entry in a database with new information or creates a new entry if one does not already exist. It compares the collected device information with the existing database entry and updates the record if there are differences. The function is designed to work with a generic database object and a specific device collection.

.PARAMETER CollectedInformation
A hashtable or custom object containing the device information collected from an external source, such as Workspace ONE.

.PARAMETER DeviceName
The name of the device. If not specified, the function will use the environment variable $ENV:COMPUTERNAME as the default device name.

.EXAMPLE
$deviceInfo = @{
    DeviceID = '12345'
    SerialNumber = 'ABCDE'
    DeviceUUID = 'UUID-12345'
    OGID = 'OG-123'
    EnrollmentState = 'Enrolled'
    EnrollmentDate = '2023-01-01'
}

Update-DatabaseDeviceEntry -CollectedInformation $deviceInfo -DeviceName "Device01"

This example updates the database entry for "Device01" with the provided information. If "Device01" does not exist in the database, a new entry will be created.

.NOTES
- Ensure that the necessary database access modules and functions (Get-DatabaseEntry, Update-DatabaseEntry, Add-DatabaseEntry) are available in the script's execution context.
- The function assumes the database object and collection name are correctly configured and accessible.
- The function logs its operations, requiring a Write-Log function or similar to be available for logging.
- The actual database interactions (Get-DatabaseEntry, Update-DatabaseEntry, Add-DatabaseEntry) are abstracted and must be defined elsewhere in your script or module.
#>
    Param ($CollectedInformation, $DeviceName
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $TempData = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Device"
        $DataEntry = @{}
        if ($null -ne $TempData) {
            Write-Log -Message "Database entry already exists, updating entry with new information" -Component ${CmdletName}

            if ($deviceName.IsPresent) {
                $filter = @{ "DeviceName" = $DeviceName }
            } else {
                $filter = @{ "DeviceName" = $ENV:COMPUTERNAME }
            }

            # Define the data to be updated

            if ($TempData.SerialNumber -ne $CollectedInformation.SerialNumber) {
                Write-Log -Message "The serial number in the database is not the same as the serial number known to Workspace ONE. Adding Serial Number for updating" -Component ${CmdletName}
                $DataEntry += @{SerialNumber = $CollectedInformation.SerialNumber }
            }

            if ($TempData.EnrollmentDate -ne $CollectedInformation.EnrollmentDate) {
                Write-Log -Message "The enrollment date in the database is not the same as the enrollment date in Workspace ONE. Adding enrollment date for updating" -Component ${CmdletName}
                $DataEntry += @{EnrollmentDate = $CollectedInformation.EnrollmentDate }
            }

            if ($TempData.OGID -ne $CollectedInformation.OGID) {
                Write-Log -Message "The OG ID in the database is not the same as the OG ID in Workspace ONE. Adding OG ID for updating" -Component ${CmdletName}
                $DataEntry += @{OGID = $CollectedInformation.OGID }
            }

            if ($TempData.EnrollmentState -ne $CollectedInformation.EnrollmentState) {
                Write-Log -Message "The enrollment state in the database is not the same as the enrollment state in Workspace ONE. Adding enrollment state for updating" -Component ${CmdletName}
                $DataEntry += @{EnrollmentState = $CollectedInformation.EnrollmentState }
            }

            if ($TempData.DeviceUUID -ne $CollectedInformation.DeviceUUID) {
                Write-Log -Message "The Device UUID in the database is not the same as the Device UUID in Workspace ONE. Adding Device UUID for updating" -Component ${CmdletName}
                $DataEntry += @{DeviceUUID = $CollectedInformation.DeviceUUID }
            }

            if ($TempData.DeviceID -ne $CollectedInformation.DeviceID) {
                Write-Log -Message "The device ID in the database is not the same as the device ID in Workspace ONE. Adding Device ID for updating" -Component ${CmdletName}
                $DataEntry += @{DeviceID = $CollectedInformation.DeviceID }
            }

            if ($null -ne $DataEntry) {
                Update-DatabaseEntry -Database $DatabaseObject -CollectionName "Device" -Filter $filter -UpdateData $DataEntry
            } else {
                Write-Log -Message "No data was selected to be updated" -Component ${CmdletName}
            }

        } else {

            $entryData = @{
                "DeviceName"      = $ENV:COMPUTERNAME
                "DeviceID"        = if ($null -ne $CollectedInformation.DeviceID) { $CollectedInformation.DeviceID }else { "" }
                "SerialNumber"    = if ($null -ne $CollectedInformation.DeviceID) { $CollectedInformation.DeviceID }else { $DeviceSerial }
                "DeviceUUID"      = if ($null -ne $CollectedInformation.DeviceUUID) { $CollectedInformation.DeviceUUID }else { "" }
                "OGID"            = if ($null -ne $CollectedInformation.OGID) { $CollectedInformation.OGID }else { "" }
                "EnrollmentState" = if ($null -ne $CollectedInformation.EnrollmentState) { $CollectedInformation.EnrollmentState }else { "" }
                "EnrollmentDate"  = if ($null -ne $CollectedInformation.EnrollmentDate) { $CollectedInformation.EnrollmentDate }else { "" }
                "LastCheck"       = $TodayString
            }
            Add-DatabaseEntry -Database $databaseObject -CollectionName "Device" -Data $entryData

        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-DatabaseDeviceEntry

#region Update-DatabaseDiskSpaceEntry
Function Update-DatabaseDiskSpaceEntry {
    <#
.SYNOPSIS
Updates disk space information in the database.

.DESCRIPTION
This function updates disk space information in the database based on the collected information, mode, and status provided. It handles initial disk space entries, as well as updating entries for different cleanup modes and statuses. Disk space information includes disk space before and after cleanup, total cleared space, and session cleared space.

.EXAMPLE
Update-DatabaseDiskSpaceEntry -CollectedInformation $CollectedInfo -Mode "CleanupMode" -Status "Completed" -Override

.NOTES
This function is typically used in conjunction with disk cleanup operations to maintain records of disk space usage and cleanup activities.
#>
    Param ($CollectedInformation,
        $Mode,
        $Status,
        [switch]$Override
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        switch ($mode) {
            initial {
                $TempData = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace"

                $entryData = @(
                    @{
                        "Date"           = $Global:TodayString
                        "Action"         = "Initial-DiskCleanup"
                        "DiskSpacePrior" = $CollectedInformation.FreeSpace
                        "DiskSpaceAfter" = $CollectedInformation.FreeSpace
                        "Status"         = "Completed"
                    },
                    @{
                        "Date"           = $Global:TodayString
                        "Action"         = "Initial-ProfileCleanup"
                        "DiskSpacePrior" = $CollectedInformation.FreeSpace
                        "DiskSpaceAfter" = $CollectedInformation.FreeSpace
                        "Status"         = "Completed"
                    }
                )

                if ($null -eq ($tempData | Where-Object { $_.Action -like "Initial-*" })) {
                    Add-DatabaseEntry -Database $databaseObject -CollectionName "DiskSpace" -Data $entryData
                } elseif ($Override -eq $true) {
                    foreach ($entry in $entryData) {
                        $Filter = @{"Action" = $entry.Action }
                        Update-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace" -UpdateData $entry -Filter $Filter
                    }
                } else {
                    Write-Log -Message "An initial value already exists for this device and will not be updated" -Component ${CmdletName}
                }

            }
            Default {

                # Get the initial entry for the mode
                $Filter = @{"Action" = "Initial-$Mode" }
                $initialEntry = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace" -Filter $Filter

                switch ($Status) {
                    Start {
                        $Filter = @{"Action" = "$Mode" }
                        $tempLastEntry = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace" -Filter $Filter

                        $LastEntry = $tempLastEntry | Where-Object { $_.Status -eq "Completed" } | Select-Object -Last 1

                        if ($null -eq $LastEntry) {
                            $LastEntry = $InitialEntry
                        }

                        $entryData = @{
                            "Date"              = $Global:TodayString
                            "Action"            = $Mode
                            "DiskSpacePrior"    = $CollectedInformation.FreeSpace
                            "Status"            = $Status
                            "TotalClearedSpace" = $LastEntry.TotalClearedSpace
                        }

                        Add-DatabaseEntry -Database $databaseObject -CollectionName "DiskSpace" -Data $entryData

                        Write-Log -Message "Current Free Space: $($CollectedInformation.FreeSpace) GB" -Component ${CmdletName}
                        Write-Log -Message "Total Free Space Percentage: $($CollectedInformation.FreePercentage)%" -Component ${CmdletName}
                        Write-Log -Message "Current Total Space Cleaned: $($LastEntry.TotalClearedSpace) GB" -Component ${CmdletName}
                    }
                    Completed {
                        $Filter = @{"Action" = "$Mode" }
                        $tempLastEntry = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace" -Filter $Filter

                        if (($tempLastEntry | Where-Object { $_.Status -eq "Start" }).Count -gt 1) {
                            Write-Log -Message "More than one entry in the database is listed as 'Started'. This could mean that a previous attempt failed and did not finish correctly." -Component ${CmdletName}
                            $LastEntry = $tempLastEntry | Where-Object { $_.Status -eq "Start" } | Select-Object -Last 1
                        } else {
                            $LastEntry = $tempLastEntry | Where-Object { $_.Status -eq "Start" } | Select-Object -Last 1
                        }

                        if ($null -eq $LastEntry) {
                            $LastEntry = $InitialEntry
                        }

                        $EntryData = @{}
                        $CalculatedClearedSpace = $CollectedInformation.FreeSpace - $LastEntry.DiskSpacePrior
                        $TotalClearedSpace = $LastEntry.TotalClearedSpace + $CalculatedClearedSpace
                        $entryData["SessionClearedSpace"] = $CalculatedClearedSpace
                        $entryData["TotalClearedSpace"] = $TotalClearedSpace
                        $entryData["Status"] = "Completed"
                        $entryData["DiskSpaceAfter"] = $CollectedInformation.FreeSpace
                        $Filter = @{"_id" = $LastEntry._id }
                        Update-DatabaseEntry -Database $DatabaseObject -CollectionName "DiskSpace" -UpdateData $entryData -Filter $Filter

                        Write-Log -Message "Current Free Space: $($CollectedInformation.FreeSpace) GB" -Component ${CmdletName}
                        Write-Log -Message "Total Free Space Percentage: $($CollectedInformation.FreePercentage)%" -Component ${CmdletName}
                        Write-Log -Message "Current Total Space Cleaned: $($TotalClearedSpace) GB" -Component ${CmdletName}
                        Write-Log -Message "Free Space Cleared This Sesssion: $($CalculatedClearedSpace)" -Component ${CmdletName}
                    }
                }
            }
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-DatabaseDiskSpaceEntry

#region Update-DatabaseUserEntry
Function Update-DatabaseUserEntry {
    <#
.SYNOPSIS
Updates user entries in the database with the provided information.

.DESCRIPTION
This function updates user entries in the database with the provided information, such as user UPN, username, domain, SID, login time, logoff time, profile path, user ID, action, and enrollment status. It checks if the user entry already exists in the database based on SID or username, and either adds a new entry or updates the existing one accordingly.

.PARAMETER CollectedInformation
Specifies the information collected about the user to update in the database.

.EXAMPLE
Update-DatabaseUserEntry -CollectedInformation $UserInfo

.NOTES
This function is typically used to update user information in the database during script execution.
#>
    Param ($CollectedInformation
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        if ($null -ne $CollectedInformation.SID) {
            $Filter = @{"SID" = $CollectedInformation.SID }
            $TempUserData = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Users" -Filter $Filter
        }

        if (($null -ne $CollectedInformation.Username) -and ($null -eq $TempUserData)) {
            $Filter = @{"Username" = $CollectedInformation.Username }
            $TempUserData = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Users" -Filter $Filter
        }

        # Check for Active User Flag
        if ($null -ne $CollectedInformation.ActiveUser) {
            $ActiveUser = if ($CollectedInformation.ActiveUser -eq $false) { $false } else { $true }
        } elseif ($null -ne $TempUserData.ActiveUser) {
            $ActiveUser = $TempUserData.ActiveUser
        } else {
            $ActiveUser = $null
        }

        # Check for Enrolled User Flag
        if ($null -ne $CollectedInformation.EnrolledUser) {
            $EnrolledUser = if ($CollectedInformation.EnrolledUser -eq $false) { $false } else { $true }
        } elseif ($null -ne $TempUserData.EnrolledUser) {
            $EnrolledUser = $TempUserData.EnrolledUser
        } else {
            $EnrolledUser = $null
        }

        # Check for Enrollment User Flag
        if ($null -ne $CollectedInformation.EnrollmentUser) {
            $EnrollmentUser = if ($CollectedInformation.EnrollmentUser -eq $false) { $false } else { $true }
        } elseif ($null -ne $TempUserData.EnrollmentUser) {
            $EnrollmentUser = $TempUserData.EnrollmentUser
        } else {
            $EnrollmentUser = $null
        }

        # Check for User UPN
        if ($null -ne $CollectedInformation.userUPN) {
            $UserUPN = $CollectedInformation.userUPN
        } elseif ($null -ne $TempUserData.userUPN) {
            $UserUPN = $TempUserData.userUPN
        } else {
            $UserUPN = $null
        }

        # Check for Username
        if ($null -ne $CollectedInformation.Username) {
            $Username = $CollectedInformation.Username
        } elseif ($null -ne $TempUserData.Username) {
            $Username = $TempUserData.Username
        } else {
            $Username = $null
        }

        # Check for Domain
        if ($null -ne $CollectedInformation.Domain) {
            $Domain = $CollectedInformation.Domain
        } elseif ($null -ne $TempUserData.Domain) {
            $Domain = $TempUserData.Domain
        } else {
            $Domain = $null
        }

        # Check for SID
        if ($null -ne $CollectedInformation.SID) {
            $SID = $CollectedInformation.SID
        } elseif ($null -ne $TempUserData.SID) {
            $SID = $TempUserData.SID
        } else {
            $SID = $null
        }

        # Check for CIMLastUseTime
        if ($null -ne $CollectedInformation.CIMLastUseTime) {
            $CIMLastUseTime = Format-Date -Date $CollectedInformation.CIMLastUseTime
        } elseif ($null -ne $TempUserData.CIMLastUseTime) {
            $CIMLastUseTime = $TempUserData.CIMLastUseTime
        } else {
            $CIMLastUseTime = $null
        }

        # Check for RegistryLastUseTime
        if ($null -ne $CollectedInformation.RegistryLastUseTime) {
            $RegistryLastUseTime = Format-Date -Date $CollectedInformation.RegistryLastUseTime
        } elseif ($null -ne $TempUserData.RegistryLastUseTime) {
            $RegistryLastUseTime = $TempUserData.RegistryLastUseTime
        } else {
            $RegistryLastUseTime = $null
        }

        # Check for EventLogDate
        if ($null -ne $CollectedInformation.EventLogDate) {
            $EventLogDate = Format-Date -Date $CollectedInformation.EventLogDate
        } elseif ($null -ne $TempUserData.EventLogDate) {
            $EventLogDate = $TempUserData.EventLogDate
        } else {
            $EventLogDate = $null
        }

        # Check for LastLogon
        if ($null -ne $CollectedInformation.LastLogon) {
            $LastLogon = Format-Date -Date $CollectedInformation.LastLogon
        } elseif ($null -ne $TempUserData.LastLogon) {
            $LastLogon = $TempUserData.LastLogon
        } else {
            $LastLogon = $null
        }

        # Check for ProfileAge
        if ($null -ne $CollectedInformation.ProfileAge) {
            $ProfileAge = $CollectedInformation.ProfileAge
        } elseif ($null -ne $TempUserData.ProfileAge) {
            $ProfileAge = $TempUserData.ProfileAge
        } else {
            $ProfileAge = $null
        }

        # Check for Path
        if ($null -ne $CollectedInformation.Path) {
            $Path = $CollectedInformation.Path
        } elseif ($null -ne $TempUserData.Path) {
            $Path = $TempUserData.Path
        } else {
            $Path = $null
        }

        # Check for UserID
        if ($null -ne $CollectedInformation.UserID) {
            $UserID = $CollectedInformation.UserID
        } elseif ($null -ne $TempUserData.UserID) {
            $UserID = $TempUserData.UserID
        } else {
            $UserID = $null
        }

        # Check for Action
        if ($null -ne $CollectedInformation.Action) {
            $Action = $CollectedInformation.Action
        } elseif ($null -ne $TempUserData.Action) {
            $Action = $TempUserData.Action
        } else {
            $Action = $null
        }

        # Check for IsConsoleSession
        if ($null -ne $CollectedInformation.IsConsoleSession) {
            $IsConsoleSession = $CollectedInformation.IsConsoleSession
        } elseif ($null -ne $TempUserData.IsConsoleSession) {
            $IsConsoleSession = $TempUserData.IsConsoleSession
        } else {
            $IsConsoleSession = $null
        }

        # Check for IsCurrentSession
        if ($null -ne $CollectedInformation.IsCurrentSession) {
            $IsCurrentSession = $CollectedInformation.IsCurrentSession
        } elseif ($null -ne $TempUserData.IsCurrentSession) {
            $IsCurrentSession = $TempUserData.IsCurrentSession
        } else {
            $IsCurrentSession = $null
        }

        $entryData = @{
            UserUPN             = $UserUPN
            Username            = $Username
            Domain              = $Domain
            SID                 = $SID
            CIMLastUseTime      = $CIMLastUseTime
            RegistryLastUseTime = $RegistryLastUseTime
            EventLogDate        = $EventLogDate
            LastLogon           = $LastLogon
            ProfileAge          = $ProfileAge
            Path                = $Path
            UserID              = $UserID
            Action              = $Action
            ActiveUser          = $ActiveUser
            EnrolledUser        = $EnrolledUser
            EnrollmentUser      = $EnrollmentUser
            IsConsoleSession    = $IsConsoleSession
            IsCurrentSession    = $IsCurrentSession
        }

        if ($null -eq $TempUserData) {
            $tempEntryData = @{
                SID = $entryData.SID
            }
            Add-DatabaseEntry -Database $databaseObject -CollectionName "Users" -Data $tempEntryData

            $Filter = @{"SID" = $entryData.SID }
            $TempUserData = Get-DatabaseEntry -Database $DatabaseObject -CollectionName "Users" -Filter $Filter

            $Filter = @{"_id" = $($TempUserData._id) }
            Update-DatabaseEntry -Database $databaseObject -CollectionName "Users" -UpdateData $entryData -Filter $Filter
        } else {
            $Filter = @{"_id" = $($TempUserData._id) }
            Update-DatabaseEntry -Database $databaseObject -CollectionName "Users" -UpdateData $entryData -Filter $Filter
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-DatabaseUserEntry

#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================
#region Script Body
try {
    Write-ScriptHeaderOrFooter -Header
    [string] ${CmdletName} = $MyInvocation.MyCommand.Name

    Write-Log -Message "Run mode: $Runmode" -Component ${CmdletName} -DebugMessage

    switch ($RunMode.ToLower()) {
        "first-run" {
            # Create database
            try {
                $DatabaseObject = Connect-Database -DatabasePath $DefaultDatabasePath -Credentials $DatabaseConnectionCreds
            } catch {
                Write-Log -Message "An attempt was made to connect to the database located at path $DefaultDatabasePath however it is being used by another process. The script will now exit" -Component ${CmdletName}
                Exit-Script -ExitCode (Get-ErrorCode -Reason "Database locked")
            }

            # Populate database with things that wont change e.g. device ID
            $Global:VariableTable = Initialize-ScriptVariables -Agency "Agency1"

            if ($Global:VariableTable.Agency -eq "Unknown") {
                $ExitDetails = Get-ErrorCode -Reason "Unknown Agency"
                Exit-Script -ExitCode $ExitDetails.Code -ExitMessage $ExitDetails.Reason
            }
            [string]$Global:ScriptSection = "Populating Device Information"
            # Retrieve API information regarding the device
            $DeviceInformation = Get-WS1DeviceInformation -LocalDevice

            if ($null -eq $DeviceInformation) {
                Write-Log -Message "No information was returned for the device in Workspace ONE. The script is dependent on information returned from the server, exiting script." -Component ${CmdletName}
            }

            if ($null -ne $DeviceInformation) {
                if ($DeviceInformation.ErrorCode) {
                    Write-Log -Message "An error occured while attempting to gather information via API. At least one of the tasks requires information from the API therefore the script is forcing an exit" -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: $($DeviceInformation.ErrorCode)")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($DeviceInformation.ErrorCode)" -Component ${CmdletName}
                        break
                    }
                } elseif (($DeviceInformation.DeviceFriendlyName.Count -gt 1) -or ($DeviceInformation.Device_Friendly_Name.Count -gt 1)) {
                    Write-Log -Message "Multiple records for the device have been returned by the API command meaning that a duplicate entry exists. The script is not designed to handle duplicate device records therefore the script will exit" -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: Duplicate Record")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($DeviceInformation.ErrorCode)" -Component ${CmdletName}
                        break
                    }
                } elseif ($null -ne $DeviceInformation.ID.Value) {
                    $Global:VariableTable.Device.DeviceID = $DeviceInformation.Id.Value
                    $Global:VariableTable.Device.EnrollmentState = if ($DeviceInformation.EnrollmentStatus) { $DeviceInformation.EnrollmentStatus }else { $DeviceInformation.Enrollment_Status }
                    $Global:VariableTable.Device.DeviceUUID = $DeviceInformation.uuid
                    $Global:VariableTable.Device.OGID = $DeviceInformation.LocationGroupID.ID.Value
                    $Global:VariableTable.Device.EnrollmentDate = $DeviceInformation.LastEnrolledOn
                    $Global:VariableTable.EnrolledUser.Username = $DeviceInformation.Username
                    $Global:VariableTable.EnrolledUser.UserUPN = $DeviceInformation.UserEmailAddress
                } else {
                    Write-Log -Message "An error occured while attempting to gather information via API. At least one of the tasks requires information from the API therefore the script is forcing an exit" -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: $($DeviceInformation.ErrorCode)")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($DeviceInformation.ErrorCode)" -Component ${CmdletName}
                        break
                    }
                }
            } else {
                Write-Log -Message "An error occured while attempting to gather information via API. At least one of the tasks requires information from the API therefore the script is forcing an exit" -Severity 3 -CmdletName ${CmdletName}
                if (!$isTesting) {
                    Exit-Script -ExitCode (Get-ErrorCode -Reason "API: $($DeviceInformation.ErrorCode)")
                } else {
                    Write-Log -Message "Script Exit with message: API: $($DeviceInformation.ErrorCode)" -Component ${CmdletName}
                    break
                }
            }

            $UpdatedInformation = [PSCustomObject]@{
                DeviceID        = $Global:VariableTable.Device.DeviceID
                DeviceName      = $Global:VariableTable.Device.Name
                DeviceUUID      = $Global:VariableTable.Device.DeviceUUID
                EnrollmentDate  = $Global:VariableTable.Device.EnrollmentDate
                EnrollmentState = $Global:VariableTable.Device.EnrollmentState
                LastCheck       = $TodayString
                OGID            = $Global:VariableTable.Device.OGID
                SerialNumber    = $Global:VariableTable.Device.SerialNumber
            }

            Update-DatabaseDeviceEntry -CollectedInformation $UpdatedInformation
            $EnrollmentSIDs = Get-EnrollmentIDs -Return

            $UserInformation = @(
                [PSCustomObject]@{
                    UserUPN    = $Global:VariableTable.ActiveUser.UserUPN
                    Username   = $Global:VariableTable.ActiveUser.Username
                    Domain     = $Global:VariableTable.ActiveUser.Domain
                    SID        = $Global:VariableTable.ActiveUser.SID
                    ActiveUser = $true
                },
                [PSCustomObject]@{
                    UserUPN      = $($Global:VariableTable.EnrolledUser.UserUPN)
                    Username     = $($Global:VariableTable.EnrolledUser.Username)
                    UserID       = $DeviceInformation.userid.id.value
                    EnrolledUser = $true
                },
                [PSCustomObject]@{
                    UserUPN        = $EnrollmentSIDs.UserUPN
                    Username       = $EnrollmentSIDs.Username
                    SID            = $EnrollmentSIDs.SID
                    EnrollmentUser = $true
                }
            )

            foreach ($UserData in $UserInformation) {
                Update-DatabaseUserEntry -CollectedInformation $UserData
            }

            # Getting the baseline disk space statistics
            $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive
            Update-DatabaseDiskSpaceEntry -Mode "Initial" -CollectedInformation $DiskStatistics

            ##! Check to see if the reg keys are there, if they are add the information into the database
            #Convert-FromRegistryDatabase

            $DatabaseObject.Dispose()

            Write-Log -Message "First Run complete" -Component ${CmdletName}
            $ExitDetails = Get-ErrorCode -Reason "Completed first run"
            Exit-Script -ExitCode $ExitDetails.Code -ExitMessage $ExitDetails.Reason
        }
        "daily" {
            # Run things that are common to all modes
            # Initialise the database and extract information
            # Check for updates
            # Fill in missing information

            Write-Log -Message "Initialising database" -Component ${CmdletName}
            $DatabaseObject = Connect-Database -DatabasePath $DefaultDatabasePath -Credentials $DatabaseConnectionCreds
            #$null = Update-LatestVersion

            # 00: Create global variable hash table to be used elsewhere in the script
            Write-Log -Message "Initialising Script Variables" -Component ${CmdletName}
            $Global:VariableTable = Initialize-ScriptVariables -Agency "Agency1"
            Write-Log -Message "Variable table initialised" -Component ${CmdletName} -DebugMessage

            if ($Global:VariableTable.Agency -eq "Unknown") {
                $ExitDetails = Get-ErrorCode -Reason "Unknown Agency"
                Exit-Script -ExitCode $ExitDetails.Code -ExitMessage $ExitDetails.Reason
            }

            # TODO: add in mechanism to determine what is the management source

            # Get Tasks to perform
            $Global:ScriptSection = "Task Check"
            $RegPath = (Convert-RegistryPath -Key "$($Global:VariableTable.RegKeyPaths.Company)\HealthCheck\$RunMode")
            if (Test-Path -Path $RegPath) {
                $tempTasksToPerform = Get-Item -Path $RegPath
            } else {
                Write-Log -Message "Unable to read variables in $RegPath. Exiting script as a precaution" -Severity 3 -CmdletName ${CmdletName}
                Exit-Script -ExitCode (Get-ErrorCode -Reason "Unable to read registry variables").Code
            }

            $TasksToPerform = [PSCustomObject]@{}
            foreach ($currentItemName in $tempTasksToPerform.Property) {
                $TasksToPerform | Add-Member -MemberType NoteProperty -Name $currentItemName -Value (Get-ItemPropertyValue -Path $RegPath -Name $currentItemName)
            }

            $Global:ScriptSection = "API Retrieval"

            <# try {
                $LastCheck = [datetime]::parseexact($DeviceInformation.LastCheck, 'yyyy-MM-dd', $null)
                if ($LastCheck.AddDays($DeviceAPICheckInterval) -le $Today) {
                    Write-Log -Message "Information exists in the database, but it has not been verified for more than $DeviceAPICheckInterval days. An API call will be made to check the information is still valid." -Component ${CmdletName}
                    ##! Work this part out, it needs to validate that the database is still correct
                    ##! You  are up to here - 15/02/24
                    ##! Skipping due to time 28/02/24, will come back to it for future versions
                }
            } catch {
                Write-Host "Unable to validate if the information is current"
            } #>

            try {
                $TagInformation = Get-WS1DeviceTags
            } catch {
                Write-Log -Message "Unable to retrieve tag information via API therefore the script is unable to confirm if the killswitch has been engaged. The script will now exit out of caution." -Severity 3 -Component ${CmdletName}
                Exit-Script -ExitCode (Get-ErrorCode -Reason "API: Unable to confirm if killswitch has been engaged")
            }

            if ($null -eq $TagInformation) {
                if ($TagInformation.ErrorCode) {
                    Write-Log -Message "An error occured while attempting to gather information via API. At least one of the tasks requires information from the API therefore the script is forcing an exit" -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: $($TagInformation.ErrorCode)")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($TagInformation.ErrorCode)" -Component ${CmdletName}
                    }
                } elseif ($TagInformation.Username.Count -gt 1) {
                    Write-Log -Message "Unknown error occured when attempting to get tag information about the device. The script will exit." -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: Unable to retrieve tag information")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($TagInformation.ErrorCode)" -Component ${CmdletName}
                    }
                } else {
                    Write-Log -Message "Unknown error occured when attempting to get tag information about the device. The script will exit." -Severity 3 -CmdletName ${CmdletName}
                    if (!$isTesting) {
                        Exit-Script -ExitCode (Get-ErrorCode -Reason "API: Unable to retrieve tag information")
                    } else {
                        Write-Log -Message "Script Exit with message: API: $($TagInformation.ErrorCode)" -Component ${CmdletName}
                    }
                }
            } else {
                if (($TagInformation.tags).Count -ne 0) {
                    $Global:VariableTable.Device.Tags = $TagInformation.tags
                    Write-Log -Message $Global:VariableTable.Device.Tags.Name -Component ${CmdletName} -DebugMessage
                } else {
                    Write-Log -Message "No tags returned for this device" -Component ${CmdletName} -DebugMessage
                }
            }

            $Global:ScriptSection = "Kill Switch Check"
            Write-Log -Message "Checking device for kill switch" -Component ${CmdletName}
            if ($Global:VariableTable.Device.Tags.Name -contains $Global:VariableTable.KillSwitch) {
                [bool]$KillSwitchEngaged = $true
            } else {
                [bool]$KillSwitchEngaged = $false
            }
            Write-Log -Message "Killswitch Tag: $($Global:VariableTable.KillSwitch)" -Component ${CmdletName} -DebugMessage
            Write-Log -Message "Killswitch: $KillSwitchEngaged" -Component ${CmdletName} -DebugMessage
        }
        Default {
        }
    }

    if ($KillSwitchEngaged -eq $true) {
        Write-Log -Message "Killswitch engaged, existing script" -Component ${CmdletName} -Severity 3
        Exit-Script -ExitCode 9999
    } else {
        <# $Global:ScriptSection = "Enrollment ID"
        $EnrollmentIDS = Get-EnrollmentIDs -Return

        # Check the SID to make sure the name is correct

        $EnrollmentIDSID = $EnrollmentIDS.SID

        $ADAccount = Get-ADUser -Identity $EnrollmentIDSID

        if ($EnrollmentIDS.UserUPN -ne $ADAccount.UserPrincipalName) {
            ##! Work this out later
        }

        Write-Log -Message "Comparing user information" -Component ${CmdletName}
        if ($Global:VariableTable.EnrollmentUser.Username -ieq $Global:VariableTable.EnrolledUser.Username) {
            Write-Log -Message "Enrollment, and Enrolled user are the same" -Component ${CmdletName}
        } else {
            Write-Log -Message "Enrollment, and Enrolled user are not the same" -Component ${CmdletName}
            Write-Log -Message "Enrollment user :: $($Global:VariableTable.EnrollmentUser.Username)" -Component ${CmdletName}
            Write-Log -Message "Enrolled :: $($Global:VariableTable.EnrolledUser.Username)" -Component ${CmdletName}
            Write-Log -Message "Active user :: $($Global:VariableTable.ActiveUser.Username)" -Component ${CmdletName}
        } #>

        switch ($RunMode.ToLower()) {
            "daily" {
                Write-Log -Message "Running daily tasks" -Component ${CmdletName}
                foreach ($task in $TasksToPerform.PSObject.Properties ) {
                    if ($task.Value -eq $true) {
                        switch ($task.Name) {
                            DiskCleanup { Initialize-DiskCleanup }
                            ProfileCleanup { Initialize-ProfileCleanup }
                            BitLocker { Update-BitLockerKey }
                            ADSite { Update-ADSite }
                            Default {}
                        }
                    }
                }

                Write-Log -Message "Updating the registry keys for WS1 sensors" -Component ${CmdletName}

                $DiskSpaceStatistics = Get-DatabaseEntry -Database $databaseObject -CollectionName "DiskSpace"

                $ProfileClean = $DiskSpaceStatistics | Where-Object { ($_.Action -eq "ProfileCleanup") -and ($_.Status -eq "Completed") } | Select-Object -Last 1

                $DiskClean = $DiskSpaceStatistics | Where-Object { ($_.Action -eq "DiskCleanup") -and ($_.Status -eq "Completed") } | Select-Object -Last 1

                $DiskStatistics = Get-DiskSpace -Drive $ENV:SystemDrive

                # Set variables to indicate value and key to set
                $RegistryPath = "$($Global:VariableTable.RegKeyPaths.Company)\ProfileCleanup"

                # Create the key if it does not exist
                If (-NOT (Test-Path $RegistryPath)) {
                    New-Item -Path $RegistryPath -Force | Out-Null
                }

                # Now set the value
                New-ItemProperty -Path $RegistryPath -Name "DiskFreePercentage" -Value $DiskStatistics.FreePercentage -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "DiskFreeSpace" -Value $ProfileClean.DiskSpaceAfter -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "TotalClearedSpace" -Value $ProfileClean.TotalClearedSpace -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "LastClearedSpace" -Value $ProfileClean.SessionClearedSpace -PropertyType String -Force | Out-Null

                $RegistryPath = "$($Global:VariableTable.RegKeyPaths.Company)\DiskCleanup"

                # Create the key if it does not exist
                If (-NOT (Test-Path $RegistryPath)) {
                    New-Item -Path $RegistryPath -Force | Out-Null
                }

                New-ItemProperty -Path $RegistryPath -Name "TotalClearedSpace" -Value $DiskClean.TotalClearedSpace -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "LastClearedSpace" -Value $DiskClean.SessionClearedSpace -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "DiskFreePercentage" -Value $DiskStatistics.FreePercentage -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $RegistryPath -Name "DiskFreeSpace" -Value $DiskClean.DiskSpaceAfter -PropertyType String -Force | Out-Null


            }
            "logon" {
                <#
        03: Check that the logged on user is the assigned user, and OMADM user
            Switch if required
        06: Backup printer mappings for each user
        07: Check if the assigned user is a local admin, if so add a tag
        11: Check for pending reboots and prompt if there are any
        XX: Check that AwWindowslpc.exe is running as the logged on user, if not then kill the process, kill 'taskmanager' process and it will auto restart
        #>
                Write-Log -Message "Running Logon tasks" -Component ${CmdletName}
                foreach ($task in $TasksToPerform.PSObject.Properties ) {
                    if ($task.Value -eq $true) {
                        switch ($task.Name) {
                            UserSwitch { Initialize-UserSwitch }
                            Default {}
                        }
                    }
                }
            }
            "logoff" {
                Write-Log -Message "Running Logoff tasks" -Component ${CmdletName}
                foreach ($task in $TasksToPerform.PSObject.Properties ) {
                    if ($task.Value -eq $true) {
                        switch ($task.Name) {
                            Default {}
                        }
                    }
                }
            }
            "startup" {
                Write-Log -Message "Running Startup tasks" -Component ${CmdletName}
                foreach ($task in $TasksToPerform.PSObject.Properties ) {
                    if ($task.Value -eq $true) {
                        switch ($task.Name) {
                            ADSite { Update-ADSite }
                            CheckLocalAdmin { Get-LocalAdminMembers }
                            Default {}
                        }
                    }
                }
            }
            "event" {
                switch ($EventID) {
                    condition {
                        Update-ADSite
                    }
                    Default {}
                }
            }
            Default {}
        }
        $Global:ScriptSection = "Finalisation"

    }
    $DatabaseObject.Dispose()
    Exit-Script -ExitCode $mainExitCode
} catch {
    $DatabaseObject.Dispose()
    [int32]$mainExitCode = 60001
    [string]$mainErrorMessage = "$(Resolve-Error)"
    Write-Log -Message $mainErrorMessage -Severity 3 -Component $deployAppScriptFriendlyName
    Exit-Script -ExitCode $mainExitCode
}
#endregion
##*=============================================
##* END SCRIPT BODY
##*=============================================
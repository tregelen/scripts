<#
.SYNOPSIS
    <Overview of script>
.DESCRIPTION
    <Brief description of script>
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
    <Inputs if any, otherwise state None>
.OUTPUTS
    <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
    Version:        1.0
    Author:         <Name>
    Creation Date:  <Date>
    Purpose/Change: Initial script development
.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>
#>
##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration
[CmdletBinding(SupportsShouldProcess)]
param([bool]$IsTesting, [string]$DatabaseName
)
#region Version
$ScriptVersion = "1.24.02.1" # 'Major.Year.Month.Increment'

##* Do not modify section below
[string]$scriptDirectory = $PSScriptRoot
[string]$Global:InvokingScriptFileName = $PSCommandPath.Replace("$PSScriptRoot\",$null)
[string]$Resources = "$scriptDirectory\Resources"
[string]$DefaultDatabasePath = "$Resources\Database\$DatabaseName.db"
[string]$AssemblyPath = "$Resources\Assembly"
[string]$ImagesPath = "$Resources\Images"
[string]$ModulesPath = "$Resources\Modules"
[string]$XAMLPath = "$Resources\XAML"
[Boolean]$DisableLogging = $False
[decimal]$UtilitiesLogMaxSize = 10
[string]$Global:ScriptSection = "Initalisation"
[string]$LogStyle = "CMTrace"
[boolean]$CompressLogs = $false
[string]$logTempFolder = "$ENV:Temp"
[string]$LogDir = "$ENV:ProgramData\DXC Technology\Logs"
[boolean]$LogWriteToHost = $true
[boolean]$LogDebugMessage = $false
[int32]$mainExitCode = 0

$IsTesting = $false
if ($isTesting -eq $true) {
    [string]$scriptDirectory = "C:\Users\awhittaker4\OneDrive - DXC Production\Git\Scripts\Workstation-HealthCheck"
    [string]$Global:InvokingScriptFileName = "Workstation-HealthCheck.ps1"
    [string]$Resources = "$scriptDirectory\Resources"
    [string]$DefaultDatabasePath = "$Resources\Database\$($InvokingScriptFileName.Replace(".ps1",".db"))"
    [string]$AssemblyPath = "$Resources\Assembly"
    [string]$ImagesPath = "$Resources\Images"
    [string]$ModulesPath = "$Resources\Modules"
    [string]$XAMLPath = "$Resources\XAML"
}

##* Do not modify section above

#endregion
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
    File Name      : Add-DatabaseEntry.ps1
    Author         : [Your Name]
    Prerequisite   : PowerShell V5
    Copyright 2023 - [Your Company Name]
    Version History: 1.1 (Updated to support multiple entries)
                     1.0 (Initial release)
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
            $collection = $Database.GetCollection($CollectionName)

            # Add each entry to the collection
            foreach ($entry in $Data) {
                $BSONMapper = [LiteDB.BSONMapper]::New()

                $collection.Insert($BSONMapper.ToDocument($Entry)) | Out-Null
            }

            Write-Output "Entries added to collection '$CollectionName' in the LiteDB database."
        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to add entries to the LiteDB database. $_" -Severity 3
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}

#endregion Add-DatabaseEntry
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
    Prerequisite   : PowerShell V5
    Copyright 2023 -DXC Technology
    Version History: 1.0 (Initial release)
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
                New-Item -Path $Parent -ItemType Directory -ErrorAction Stop | Out-Null
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
            Write-Log -Message "Unable to create or open the database in $Parent :: $_" -Severity 3
            Throw $_
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Connect-Database
#region Convert-BsonDocumentToPSCustomObject
Function Convert-BsonDocumentToPSCustomObject {
    param (
        [LiteDB.BsonDocument]$BsonDocument
    )

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
    return [PSCustomObject]$hashtable
}
#endregion Convert-BsonDocumentToPSCustomObject
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
        $ExitCode,
        $ExitMessage,
        [switch]$ScriptError,
        [switch]$Restart
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

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
            Write-ScriptHeaderOrFooter -CmdletName ${CmdletName} -Footer
            Exit $ExitCode
        } else {
            Write-ScriptHeaderOrFooter -CmdletName ${CmdletName} -Footer
            Exit
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }


}
#endregion Exit-Script
#region Get-DatabaseData
Function Get-DatabaseData {
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

.PARAMETER Projection
    Specifies optional projection parameters to select specific fields.

.PARAMETER Sort
    Specifies optional sort parameters to order the results.

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    Get-DatabaseData -Database $database -CollectionName "Users"

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $filter = @{ "City" = "New York" }
    Get-DatabaseData -Database $database -CollectionName "Users" -Filter $filter

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $projection = @{ "Name" = $true; "Age" = $true }
    Get-DatabaseData -Database $database -CollectionName "Users" -Projection $projection

.EXAMPLE
    $database = Connect-Database -DatabasePath "C:\Path\To\Database.db" -ReadOnly
    $sort = @{ "Age" = 1 }
    Get-DatabaseData -Database $database -CollectionName "Users" -Sort $sort

.NOTES
    File Name      : Get-DatabaseData.ps1
    Author         : [Your Name]
    Prerequisite   : PowerShell V5
    Copyright 2023 - [Your Company Name]
    Version History: 1.1 (Enhanced retrieval methods)
                     - Added examples for projection and sorting
                     1.0 (Initial release)
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,

        [Parameter(Mandatory = $true)]
        [string]$CollectionName,

        [HashTable]$Filter = @{},

        [switch]$BSON
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

            # Build LiteDB Query
            $query = $collection.Query()

            # Add filter criteria to the query
            foreach ($key in $Filter.Keys) {
                $query = $query.Where([LiteDB.Query]::EQ($key, $Filter[$key]))
            }

            if ($BSON) {
                $results = $query.ToDocuments()
            } else {
                # Execute the query and convert results to PSCustomObject
                $results = $query.ToDocuments() | ForEach-Object {
                    Convert-BsonDocumentToPSCustomObject $_
                }
            }

            # Output the query results
            Write-Output $results
        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to retrieve data from the LiteDB database. $_" -Severity 3
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}



#endregion Get-DatabaseData
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
    Author         : Your Name
    Prerequisite   : PowerShell V2

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

            $Item = Get-DatabaseData -Filter $Filter -Database $Database -CollectionName $CollectionName -BSON

            # Check if multiple entries were found
            if ($items.Count -gt 1) {
                throw "Multiple entries found for the specified filter. Please provide a more specific filter to avoid accidental deletion."
            }

            # Check if any entry was found
            if ($items.Count -eq 0) {
                Write-Output "No entry found for the specified filter in collection '$CollectionName'. Nothing deleted."
                return
            }

            # Execute the delete
            $deleteResult = $collection.Delete($Item['_id'].RawValue)

            # Output the delete result
            Write-Output "Deleted $($deleteResult.DeletedCount) entry from collection '$CollectionName'."

        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to delete entry from the LiteDB database. $_" -Severity 3
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Remove-DatabaseEntry
#region Update-DatabaseEntry
Function Update-DatabaseEntry {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [LiteDB.LiteDatabase]$Database,

        [Parameter(Mandatory = $true)]
        [string]$CollectionName,

        [Parameter(Mandatory = $true)]
        [HashTable]$Filter,

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

            $Item = Get-DatabaseData -Filter $Filter -Database $Database -CollectionName $CollectionName -BSON
            # Convert update data hashtable to BsonDocument
            foreach ($key in $UpdateData.Keys) {
                $Item[$key] = $UpdateData[$key]
            }

            # Execute the update
            $updateResult = $collection.Update($Item)

            # Output the update result
            Write-Output "Updated $($updateResult.ModifiedCount) entry in collection '$CollectionName'."

        } catch {
            # Log an error message if an exception occurs
            Write-Log -Message "Unable to update entry in the LiteDB database. $_" -Severity 3
            throw $_
        }
    }

    End {
        # Write function footer
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}

#endregion Update-DatabaseEntry
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

    If ($Header) {
        Write-Log -Message 'Function Start' -Component $CmdletName -DebugMessage

        ## Get the parameters that the calling function was invoked with
        [string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        If ($CmdletBoundParameters) {
            Write-Log -Message "Function invoked with bound parameter(s): `n$CmdletBoundParameters" -Component $CmdletName -DebugMessage
        } Else {
            Write-Log -Message 'Function invoked without any bound parameters.' -Component $CmdletName -DebugMessage
        }
    } ElseIf ($Footer) {
        Write-Log -Message 'Function End' -Component $CmdletName -DebugMessage
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
        [decimal]$MaxLogFileSizeMB = $UtilitiesLogMaxSize,
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

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Write-ScriptHeaderOrFooter -Parameter $Value
.NOTES

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

    If ($Header) {
        $scriptSeparator = '*' * 79
        Write-Log -Message ($scriptSeparator, $scriptSeparator) -Source $appDeployToolkitName
        Write-Log -Message 'Script Start' -Component $CmdletName

        ## Get the parameters that the calling function was invoked with
        [string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
        If ($CmdletBoundParameters) {
            Write-Log -Message "Script invoked with bound parameter(s): `n$CmdletBoundParameters" -Component $CmdletName -DebugMessage
        } Else {
            Write-Log -Message 'Script invoked without any bound parameters.' -Component $CmdletName -DebugMessage
        }

        Write-Log -Message "File name: $Global:InvokingScriptFileName" -Component $CmdletName
        Write-Log -Message "File version: $ScriptVersion" -Component $CmdletName
        Write-Log -Message "************************************" -Component $CmdletName
    } ElseIf ($Footer) {
        $Global:ScriptSection = "Finalisation"
        Write-Log -Message "************************************" -Component $CmdletName
        Write-Log -Message 'Script End' -Component $CmdletName
        Write-Log -Message "************************************" -Component $CmdletName
    }
}
#endregion Write-ScriptHeaderOrFooter

#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================
#region Script Body

$Credentials = ""

if (Test-Path -Path $DefaultDatabasePath){
    Remove-Item -Path $DefaultDatabasePath -Force
}

$DatabaseObject = Connect-Database -DatabasePath "$DefaultDatabasePath" -Credentials $credentials

$AgencyentryData = @{
    Agency              = ""
    DataSource          = ""
    ApplicationDatabase = ""
    WS1Database         = ""
    ReadOnlyUsername    = ""
    ReadOnlyPassword    = ""
    WriteUsername       = ""
    WritePassword       = ""
    BaseURI             = ""
    APIUsername         = ""
    APIPassword         = ""
    APITenantKey        = ""
}
Add-DatabaseEntry -Database $DatabaseObject -CollectionName "Agency" -Data $AgencyentryData

$EnrollmentDetailsObject = @{
    DOWNLOADWSBUNDLE       = $false
    SERVER                 = ""
    LGNAME                 = ""
    USERNAME               = ""
    PASSWORD               = ""
    ASSIGNEDTOLOGGEDINUSER = "Y"
    ENROLL                 = "Y"
    IMAGE                  = "N"
}
Add-DatabaseEntry -Database $DatabaseObject -CollectionName "Enrollment" -Data $EnrollmentDetailsObject

$DatabaseObject.Dispose()

Exit-Script -ExitCode $mainExitCode
#endregion
##*=============================================
##* END SCRIPT BODY
##*=============================================
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
    Version:        0.0.3.0
    Author:         Aaron Whittaker
    Creation Date:  <Date>
    Purpose/Change: Added support for Windows 7 devices as the base

    Version:        0.0.2.0
    Author:         Aaron Whittaker
    Creation Date:  <Date>
    Purpose/Change: Initial script development
.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>
#>
##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

param([string]$Mode = "All", [switch]$Testing
)
#region Version
[version]$ScriptVersion = "0.0.4.0" # Major.Minor.Build.Revision

##* Do not modify section below
[string]$scriptDirectory = $PSScriptRoot
[string]$Global:InvokingScriptFileName = $PSCommandPath.Replace(".ps1", "-$mode.ps1")
[Boolean]$DisableLogging = $False
[decimal]$UtilitiesLogMaxSize = 10
[string]$Global:ScriptSection = "Initalisation"
[string]$UtilitiesLogStyle = "CMTrace"
[boolean]$UtilitiesCompressLogs = $false
[string]$logTempFolder = "$ENV:Temp"
[string]$UtilitiesLogDir = $scriptDirectory
[boolean]$UtilitiesLogWriteToHost = $true
[boolean]$UtilitiesLogDebugMessage = $false
$PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Detailed'
$Global:ProgressPreference = 'SilentlyContinue'
[string]$JSONPath = "$scriptDirectory\Active"
[string]$ArchivePath = "$scriptDirectory\Archive"
[bool]$Override = $true
##* Do not modify section above

if ($testing -eq $true) {
    [string]$scriptDirectory = "D:\Temp"
    [string]$Global:InvokingScriptFileName = "Workstation-ImageingAdministrator-Testing.ps1"
    [string]$JSONPath = "$scriptDirectory\Active"
    [string]$ArchivePath = "$scriptDirectory\Archive"
    [string]$UtilitiesLogDir = $scriptDirectory
}
#endregion
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings
#region Exit-Script
Function Exit-Script {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Verb-Noun -Parameter $Value
.NOTES

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
        [string]$LogType = $UtilitiesLogStyle,
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileDirectory = $(If ($UtilitiesCompressLogs) {
                $logTempFolder
            } Else {
                $UtilitiesLogDir
            }),
        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileName = (Split-Path -Path $Global:InvokingScriptFileName -Leaf),
        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullorEmpty()]
        [decimal]$MaxLogFileSizeMB = $UtilitiesLogMaxSize,
        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullorEmpty()]
        [boolean]$WriteHost = $UtilitiesLogWriteToHost,
        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true,
        [Parameter(Mandatory = $false, Position = 10)]
        [switch]$PassThru = $false,
        [Parameter(Mandatory = $false, Position = 11)]
        [switch]$DebugMessage = $false,
        [Parameter(Mandatory = $false, Position = 12)]
        [boolean]$LogDebugMessage = $UtilitiesLogDebugMessage
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
#region Start-InitialPhase
Function Start-InitialPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-InitialPhase
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        [version]$FunctionVersion = "1.0.0.0" # Major.Minor.Build.Revision
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = Get-Devices -Phase "Initial"

        foreach ($Device in $Devices) {

            <#
    1: Check if it exists in WS1
    2: Add missing details for old device
    3: Check for new device in WS1
    4: Add missing details to new device
    5: Get OU for both devices
    6: Move to tag phase
    #>
            $TempDeviceObject = New-DeviceObject
            $TempDeviceObject.CurrentPhase = "Initial"
            $TempDeviceObject.NextPhase = "Tagging"

            # Gets AD information for new and old device

            try {
                $TempAD = (Get-ADComputer -Identity $($TempDeviceObject.OldDeviceName) -Properties OperatingSystem, DistinguishedName, MemberOf)
                $TempDeviceObject.OldDeviceOS = $TempAD.OperatingSystem
                $TempDeviceObject.OldDeviceADGroups = $TempAD.MemberOf
                $TempDeviceObject.OldDeviceOU = $($TempAD.DistinguishedName.Replace("CN=$($TempDeviceObject.OldDeviceName),", ''))
            } catch {
                $TempDeviceObject.Comment += "$($TempDeviceObject.OldDeviceName) not found in AD"
                Write-Log -Message "Error retrieving AD information for $($TempDeviceObject.OldDeviceName)." -Severity 3
                if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
            }

            try {
                $TempAD = (Get-ADComputer -Identity $($TempDeviceObject.NewDeviceName) -Properties OperatingSystem, DistinguishedName, MemberOf)
                $TempDeviceObject.NewDeviceOS = $TempAD.OperatingSystem
                $TempDeviceObject.NewDeviceADGroups = $TempAD.MemberOf
                $TempDeviceObject.NewDeviceOU = $($TempAD.DistinguishedName.Replace("CN=$($TempDeviceObject.NewDeviceName),", ''))

            } catch {
                $TempDeviceObject.Comment += "$($TempDeviceObject.OldDeviceName) not found in AD"
                Write-Log -Message "Error retrieving AD information for $($TempDeviceObject.NewDeviceName)." -Severity 2
                if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
            }

            # Gets WS1 information for new and old device

            $Command = "Select DEV.FriendlyName, DEV.SerialNumber, DEV.DeviceID, DEV.EnrollmentStatusID, DEV.LocationGroupID
    FROM dbo.Device DEV
    WHERE (DEV.FriendlyName = '$($TempDeviceObject.OldDeviceName)') OR (DEV.FriendlyName = '$($TempDeviceObject.NewDeviceName)')"

            Try {
                $DeviceInformation = Invoke-SqlCommand -sqlCommand "$Command" -dataSource "$($Global:VariableObject.DataSource)" -WS1
            } catch {
                $DeviceInformation = $Null
            }

            if ($null -ne $DeviceInformation) {
                $OldDeviceInformation = $($DeviceInformation | Where-Object { $_.FriendlyName -eq $($TempDeviceObject.OldDeviceName) })
                $NewDeviceInformation = $($DeviceInformation | Where-Object { $_.FriendlyName -eq $($TempDeviceObject.NewDeviceName) })
            } else {
                $TempDeviceObject.Comment += "No information returned for $($TempDeviceObject.OldDeviceName) or $($TempDeviceObject.NewDeviceName) within WS1 database"
                Write-log -Message "No information returned for either $($TempDeviceObject.OldDeviceName) or $($TempDeviceObject.NewDeviceName)"
                if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
            }

            if ($TempDeviceObject.Status -eq "Continue") {
                if (($OldDeviceInformation.DeviceID | Select-Object -Unique).Count -gt 1) {
                    $TempDeviceObject.Comment += "$($TempDeviceObject.OldDeviceName) has a duplicate entry in Workspace ONE"
                    if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
                    Write-Log -Message "Duplicate Workspace ONE entry detected for $($TempDeviceObject.OldDeviceName)" -Severity 3

                } elseif ($null -eq $OldDeviceInformation.DeviceID) {
                    if ($TempDeviceObject.OldDeviceOS -notlike "Windows 10*") {
                        $TempDeviceObject.Comment += "$($TempDeviceObject.OldDeviceName) is not Windows 10, therefore it is not in Workspace ONE. Device will have to have a live ARP"
                        Write-Log -Message "$($TempDeviceObject.OldDeviceName) is not Windows 10, therefore it is not in Workspace ONE. Device will have to have a live ARP" -Severity 2
                        $TempDeviceObject.NextPhase = "LiveARP"
                    } else {
                        $TempDeviceObject.Comment += "$($TempDeviceObject.OldDeviceName) is not in Workspace ONE and is Windows 10+, manually confirm that it is a valid device and then set to 'Live ARP' to get the application load. If the device isn't valid, either update the device name or remove the entry."
                        Write-Log -Message "$($Device.DeviceName) not found in Workspace ONE and has been detected as Windows 10" -Severity 3
                        if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
                    }

                } else {
                    Write-Log -Message "Device Found :: $($TempDeviceObject.OldDeviceName) - $($TempDeviceObject.OldDeviceWS1ID)"
                    $TempDeviceObject.OldDeviceWS1ID = $OldDeviceInformation.DeviceID
                    $TempDeviceObject.OldDeviceSerialNumber = $OldDeviceInformation.SerialNumber
                    $TempDeviceObject.OldDeviceLocationGroupID = $OldDeviceInformation.LocationGroupID
                }

                # 4
                if (($NewDeviceInformation.DeviceID | Select-Object -Unique).Count -gt 1) {
                    $TempDeviceObject.Comment += "$($TempDeviceObject.NewDeviceName) has a duplicate entry in Workspace ONE"
                    if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
                    Write-Log -Message "Duplicate Workspace ONE entry detected for $($TempDeviceObject.NewDeviceName)" -Severity 3

                } elseif ($null -eq $NewDeviceInformation.DeviceID) {
                    $TempDeviceObject.Comment += "$($TempDeviceObject.NewDeviceName) has not yet enrolled into Workspace ONE"
                    if ($TempDeviceObject.Status -eq "Continue") { $TempDeviceObject.Status = "Retry" }
                    Write-Log -Message "$($TempDeviceObject.NewDeviceName) not yet enrolled"

                } else {
                    Write-Log -Message "New Device Found :: $($TempDeviceObject.NewDeviceName) - $($NewDeviceInformation.DeviceID)"
                    $TempDeviceObject.NewDeviceWS1ID = $NewDeviceInformation.DeviceID
                    $TempDeviceObject.NewDeviceSerialNumber = $NewDeviceInformation.SerialNumber
                    $TempDeviceObject.NewDeviceLocationGroupID = $NewDeviceInformation.LocationGroupID
                }
            }

            # Update the entry

            # Create update command

            $Command = "UPDATE $($Global:VariableObject.ApplicationTable) SET "
            if ((($null -eq $Device.DeviceSerial) -OR ($Device.DeviceSerial.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.OldDeviceSerialNumber)) {
                Write-Log -Message "Adding Serial Number to Old Device" -DebugMessage
                $Command = $Command + "DeviceSerial = '$($TempDeviceObject.OldDeviceSerialNumber)', "
            }

            if ((($null -eq $Device.DeviceWS1ID) -OR ($Device.DeviceWS1ID.ToString().Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.OldDeviceWS1ID)) {
                Write-Log -Message "Adding Workspace ONE Device ID to Old Device" -DebugMessage
                $Command = $Command + "DeviceWS1ID = '$($TempDeviceObject.OldDeviceWS1ID)', "
            }

            if ((($null -eq $Device.DeviceOG) -OR ($Device.DeviceOG.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.OldDeviceLocationGroupID)) {
                Write-Log -Message "Adding Workspace ONE Device OG to Old Device" -DebugMessage
                $Command = $Command + "DeviceOG = '$($TempDeviceObject.OldDeviceLocationGroupID)', "
            }

            <# if ($null -eq $Device.DeviceStatus) {
                Write-Log -Message "Adding Device status to Old Device" -DebugMessage
                $Command = $Command + " SET DeviceStatus = ''"
            } #>

            if ((($null -eq $Device.NewDeviceSerial) -OR ($Device.NewDeviceSerial.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.NewDeviceSerialNumber)) {
                Write-Log -Message "Adding Serial Number to New Device" -DebugMessage
                $Command = $Command + "NewDeviceSerial = '$($TempDeviceObject.NewDeviceSerialNumber)', "
            }

            if ((($null -eq $Device.NewDeviceWS1ID) -OR ($Device.NewDeviceWS1ID.ToString().Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.NewDeviceWS1ID)) {
                Write-Log -Message "Adding Workspace ONE Device ID to New Device" -DebugMessage
                $Command = $Command + "NewDeviceWS1ID = '$($TempDeviceObject.NewDeviceWS1ID)', "
            }

            if ((($null -eq $Device.NewDeviceOG) -OR ($Device.NewDeviceOG.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.NewDeviceLocationGroupID)) {
                Write-Log -Message "Adding Workspace ONE Device OG to New Device" -DebugMessage
                $Command = $Command + "NewDeviceOG = '$($TempDeviceObject.NewDeviceLocationGroupID)', "
            }

            <# if (($null -eq $Device.NewDeviceStatus) -OR ($Device.NewDeviceStatus.Length -ge 1) -OR ($Override -eq $true)) {
                # Device Status
                #Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NewDeviceStatus = '$($NewDeviceInformation.SerialNumber | Select-Object -Unique)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
            } #>

            if ((($null -eq $Device.DeviceOU) -OR ($Device.DeviceOU.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.OldDeviceOU)) {
                Write-Log -Message "Adding Device OU to Old Device" -DebugMessage
                $Command = $Command + "DeviceOU = '$($TempDeviceObject.OldDeviceOU)', "
            }
            if ((($null -eq $Device.NewDeviceOU) -OR ($Device.NewDeviceOU.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.NewDeviceOU)) {
                Write-Log -Message "Adding Device OU to Old Device" -DebugMessage
                $Command = $Command + "NewDeviceOU = '$($TempDeviceObject.NewDeviceOU)', "
            }

            if ((($null -eq $Device.Comment) -OR ($Device.Comment.Length -ge 1) -OR ($Override -eq $true)) -AND ($TempDeviceObject.Comment)) {
                Write-Log -Message "Adding Device OU to Old Device" -DebugMessage
                $Command = $Command + "Comment = '$($TempDeviceObject.Comment)', "
            }

            if (($Command.Trim()).Substring(($Command.Trim()).Length - 1) -eq ",") {
                $Command = "$(($Command.Trim()).Remove(($Command.Trim()).Length - 1, 1)) WHERE DeviceName = '$($TempDeviceObject.OldDeviceName)' AND NewDeviceName = '$($TempDeviceObject.NewDeviceName)'"
            }

            if ($testing -eq $True) {
                Write-Host "$($TempDeviceObject.OldDeviceName) - $($TempDeviceObject.NewDeviceName) moving to $($TempDeviceObject.NextPhase)"
            } else {
                Invoke-SqlCommand -sqlCommand "$Command" -ApplicationWrite
            }

            # Confirm all details are present
            if ($testing -eq $True) {
                $Command = "UPDATE $($Global:VariableObject.ApplicationTable) SET "
                if ($TempDeviceObject.Status -ne "Retry") {
                    $Command = $Command + "InitialPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")', PreviousStep = '$($TempDeviceObject.CurrentPhase)', NextStep = '$($TempDeviceObject.NextPhase)', "
                }
                $Command = $Command + "LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE DeviceName = '$($TempDeviceObject.OldDeviceName)' AND NewDeviceName = '$($TempDeviceObject.NewDeviceName)'"
                Write-Host "$command"
            } else {
                $Command = "UPDATE $($Global:VariableObject.ApplicationTable) SET "

                $DeviceInformationCheck = Get-Devices -OldDevice $($TempDeviceObject.OldDeviceName) -NewDevice $($TempDeviceObject.NewDeviceName)
                [pscustomobject]$Checks = [PSCustomObject]@{
                    OldDeviceSerial = if ($TempDeviceObject.OldDeviceSerialNumber.Length -gt 0) { if ($DeviceInformationCheck.DeviceSerial -eq $TempDeviceObject.OldDeviceSerialNumber) { $True } else { $false } }else {}
                    OldDeviceWS1ID  = if ($TempDeviceObject.OldDeviceWS1ID.Length -gt 0) { if ($DeviceInformationCheck.DeviceWS1ID -eq $TempDeviceObject.OldDeviceWS1ID) { $True } else { $false } }else {}
                    OldDeviceWS1OG  = if ($TempDeviceObject.OldDeviceLocationGroupID.Length -gt 0) { if ($DeviceInformationCheck.DeviceOG -eq $TempDeviceObject.OldDeviceLocationGroupID) { $True } else { $false } }else {}
                    OldDeviceOU     = if ($TempDeviceObject.OldDeviceOU.Length -gt 0) { if ($DeviceInformationCheck.DeviceOU -eq $TempDeviceObject.OldDeviceOU) { $True } else { $false } }else {}
                    NewDeviceSerial = if ($TempDeviceObject.NewDeviceSerialNumber.Length -gt 0) { if ($DeviceInformationCheck.NewDeviceSerial -eq $TempDeviceObject.NewDeviceSerialNumber) { $True } else { $false } }else {}
                    NewDeviceWS1ID  = if ($TempDeviceObject.NewDeviceWS1ID.Length -gt 0) { if ($DeviceInformationCheck.NewDeviceWS1ID -eq $TempDeviceObject.NewDeviceWS1ID) { $True } else { $false } }else {}
                    NewDeviceWS1OG  = if ($TempDeviceObject.NewDeviceLocationGroupID.Length -gt 0) { if ($DeviceInformationCheck.NewDeviceOG -eq $TempDeviceObject.NewDeviceLocationGroupID) { $True } else { $false } }else {}
                    NewDeviceOU     = if ($TempDeviceObject.NewDeviceOU.Length -gt 0) { if ($DeviceInformationCheck.NewDeviceOU -eq $TempDeviceObject.NewDeviceOU) { $True } else { $false } }else {}
                }

                if (($Checks.OldDeviceSerial -ne $false) -AND
                ($Checks.OldDeviceWS1ID -ne $false) -AND
                ($Checks.OldDeviceWS1OG -ne $false) -AND
                ($Checks.OldDeviceOU -ne $false) -AND
                ($Checks.NewDeviceSerial -ne $false) -AND
                ($Checks.NewDeviceWS1ID -ne $false) -AND
                ($Checks.NewDeviceWS1OG -ne $false) -AND
                ($Checks.NewDeviceOU -ne $false) ) {
                    if ($TempDeviceObject.Status -ne "Retry") {
                        $Command = $Command + "InitialPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")', PreviousStep = '$($TempDeviceObject.CurrentPhase)', NextStep = '$($TempDeviceObject.NextPhase)', "
                    }
                }


                $Command = $Command + "LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE DeviceName = '$($TempDeviceObject.OldDeviceName)' AND NewDeviceName = '$($TempDeviceObject.NewDeviceName)'"

                Invoke-SqlCommand -sqlCommand "$Command" -ApplicationWrite
            }

        }

    }

    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}

#endregion Start-InitialPhase
#region New-DeviceObject
Function New-DeviceObject {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    New-DeviceObject -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $tempDeviceObject = [PSCustomObject]@{
            OldDeviceName            = $($Device.DeviceName)
            OldDeviceOS              = ""
            OldDeviceADGroups        = ""
            OldDeviceOU              = ""
            OldDeviceWS1ID           = ""
            OldDeviceSerialNumber    = ""
            OldDeviceLocationGroupID = ""

            NewDeviceName            = $($Device.NewDeviceName)
            NewDeviceOS              = ""
            NewDeviceADGroups        = ""
            NewDeviceOU              = ""
            NewDeviceWS1ID           = ""
            NewDeviceSerialNumber    = ""
            NewDeviceLocationGroupID = ""

            Status                   = "Continue"
            CurrentPhase             = "Initial"
            NextPhase                = "Tagging"
            Comment                  = ""
        }

        Write-Output -InputObject $tempDeviceObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion New-DeviceObject
#region Get-DeviceTags
Function Get-DeviceTags {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-DeviceTags -Parameter $Value
.NOTES

#>
    Param ($OldDeviceWS1ID, $NewDeviceWS1ID
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Command = "SELECT DT.DeviceID, DAT.FriendlyName, DAT.SerialNumber, DAT.LocationGroupID, DAT.LocationGroupName, LGP.LocationGroupPath, DT.TagID, TAG.Name
FROM dbo.DeviceTag DT
LEFT JOIN dbo.Tag TAG ON DT.TagID = TAG.TagID
LEFT JOIN dbo.DeviceAttributes DAT ON DT.DeviceID = DAT.DeviceID
LEFT JOIN dbo.LocationGroupPath LGP ON DAT.LocationGroupID = LGP.LocationGroupID
WHERE DT.DeviceID = '$($OldDeviceWS1ID)' OR DT.DeviceID = '$($NewDeviceWS1ID)'"
        Try {
            $TempTagInformation = Invoke-SqlCommand -sqlCommand "$Command" -WS1
        } catch {
            $TempTagInformation = $Null
        }

        if ($null -ne $TempTagInformation) {
            Write-Output -InputObject $TempTagInformation
        } else {
            Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET Comment = 'No information returned for $($Device.DeviceName) or $($Device.NewDeviceName) within WS1 database' WHERE DeviceName = '$($Device.DeviceName)' AND NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
            Write-log -Message "No information returned for either $($Device.DeviceName) or $($Device.NewDeviceName)"
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DeviceTags
#region Get-AllTags
Function Get-AllTags {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-AllTags -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Command = "SELECT TAG.TagID, TAG.Name, TAG.LocationGroupID FROM dbo.Tag TAG"
        Try {
            $TempTagInformation = Invoke-SqlCommand -sqlCommand "$Command" -WS1
        } catch {
            $TempTagInformation = $Null
        }

        if ($null -ne $TempTagInformation) {
            Write-Output -InputObject $TempTagInformation
        } else {
            # TODO Work out how to display an error on the UI
            Write-log -Message "No tags returned, check network connectivity" -Severity 3
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-AllTags

#region Start-TaggingPhase
Function Start-TaggingPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-TaggingPhase -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = Get-Devices -Phase "Tagging"
        $AllTags = Get-AllTags
        $IgnoredTags = @()
        foreach ($TagToIgnore in $Global:VariableObject.TagsToIgnore) {
            $TempIgnore = [PSCustomObject]@{
                'Name'  = $TagToIgnore
                'TagID' = ($AllTags | Where-Object { $_.Name -like "$TagToIgnore" }).TagID
            }
            $IgnoredTags += $tempIgnore
        }
#TODO Update the translation table to be on the SQL
        $TagsToAdd = @()
        #$TranslationTable = Get-TranslationTable
        $TranslationTable = Get-Content -Raw -Path "$scriptDirectory\TranslationTable.csv" | ConvertFrom-Csv

        if ($testing -eq $True) {
            ## TESTING ##
            $TranslationTable = Get-Content -Raw -Path "D:\Scripts\Workstation-ImagingAdministrator\TranslationTable.csv" | ConvertFrom-Csv
            ## END TESTING ##
        }
        foreach ($Device in $Devices) {

            <#
            1: Get tags from old device
            2: Get tags from ARP
            3: Get tags from new device
            4: Tag any missing tags
            5: Move to ARP, Local, and AD Groups phase, if it hasnt been completed yet. If it has, move to OG phase
            #>
            $TempDeviceObject = New-DeviceObject
            $TempDeviceObject.CurrentPhase = "Tagging"
            $TempDeviceObject.NextPhase = "ARP"

            $TempTagInformation = Get-DeviceTags -OldDeviceWS1ID $($Device.DeviceWS1ID) -NewDeviceWS1ID $($Device.NewDeviceWS1ID)
            # 1 and 3
            if ($null -ne $TempTagInformation) {
                $OldDeviceTagInformation = $($TempTagInformation | Where-Object { $_.FriendlyName -eq $($Device.DeviceName) })
                $NewDeviceTagInformation = $($TempTagInformation | Where-Object { $_.FriendlyName -eq $($Device.NewDeviceName) })
            } else {
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET Comment = 'No information returned for $($Device.DeviceName) or $($Device.NewDeviceName) within WS1 database' WHERE DeviceName = '$($Device.DeviceName)' AND NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                Write-log -Message "No information returned for either $($Device.DeviceName) or $($Device.NewDeviceName)"
            }

            # 2
            If ($Device.ARPPhase.Length -gt 2) {

                # Import JSON file from ARP
                $Filename = "$JSONPath\$($Device.DeviceName)-$($Device.NewDeviceName).json"
                if (Test-Path -Path $Filename) {
                    Write-Log -Message "JSON file located for $($Device.DeviceName)-$($Device.NewDeviceName)"
                    # Check each application against the translation tables
                    $DeviceJSON = Get-Content -Raw -Path $Filename | ConvertFrom-Json
                    <# TESTING
                    if ($testing = $true) {
                        $Application = ($DeviceJSON.Programs | Where-Object { $_.DisplayName -eq "Agency2 MDE Management Tool (Win10) (x64) 2.1.646.0" })
                    }#>
                    foreach ($Application in ($DeviceJSON.Programs | Where-Object { $null -ne $_.DisplayName })) {
                        <#
                        2a: Compare against translation table for any matches
                        2b: Compare against SCCM translation table for any matches
                        2c: Add any applications to the tagging table
                        #>

                        <#
                        2ai: Check against the display name, if match move to 2aii
                        2aii: Check the version, if match move to 2aiii
                        2aiii: Add to the tagging table#>

                        # 2ai - Check name
                        $TranslatedApplication = $TranslationTable | Where-Object { $($Application.DisplayName) -match $_.DisplayName } -ErrorAction SilentlyContinue

                        if ($TranslatedApplication) {
                            $TagID = $($TranslatedApplication.WorkspaceONETagID)
                            Write-log "$($Application.DisplayName) successfully translated to $($TranslatedApplication.WorkspaceONEApplicationName) :: $TagID"

                            if ($NewDeviceTagInformation.TagID -contains $TagID ) {
                                $Action = "Existing"
                            } else {
                                $Action = "Add"
                            }

                            if ($TagID -in $IgnoredTags.TagID) {
                                Write-log -Message "$($($AllTags | Where-Object { $_.TagID -eq $TagID }).Name) is included in the list of tags to ignore"
                                $Action = "Ignore"
                            }
                            Write-log -Message "Adding $($($AllTags | Where-Object { $_.TagID -eq $TagID }).Name) to $action for $($Device.NewDeviceName)"
                            if (($TagsToAdd.TagID -contains $TagID) -and ($Action -eq ($TagsToAdd | Where-Object { $_.TagID -eq $TagID }).Action)) {
                                $($TagsToAdd | Where-Object { $_.TagID -eq $TagID }).DeviceID += $($Device.NewDeviceWS1ID)
                            } else {
                                $TempTagObject = [PSCustomObject]@{
                                    'DeviceID' = @($($Device.NewDeviceWS1ID))
                                    'TagName'  = $($AllTags | Where-Object { $_.TagID -eq $TagID }).Name
                                    'TagID'    = $TagID
                                    'Action'   = $Action
                                }
                                $TagsToAdd += $TempTagObject
                            }
                        }
                    }
                } else {
                    Write-Log -Message "No JSON file located for $($Device.DeviceName)-$($Device.NewDeviceName)" -Severity 2
                }
            }


            # 4
            foreach ($Tag in ($OldDeviceTagInformation | Where-Object { $_.Name -notlike "APPL-Deployment Devices Ending*" })) {
                if ($NewDeviceTagInformation.TagID -contains $Tag.TagID ) {
                    $Action = "Existing"
                } else {
                    $Action = "Add"
                }
                $TagID = $($Tag.TagID)
                if ($TagID -in $IgnoredTags.TagID) {
                    Write-log -Message "$($($AllTags | Where-Object { $_.TagID -eq $TagID }).Name) is included in the list of tags to ignore"
                    $Action = "Ignore"
                }
                if (($TagsToAdd.TagID -contains $TagID) -and ($Action -eq ($TagsToAdd | Where-Object { $_.TagID -eq $TagID }).Action)) {
                    $($TagsToAdd | Where-Object { ($_.TagID -eq $TagID) -AND ($_.Action -eq "$Action") }).DeviceID += $($Device.NewDeviceWS1ID)
                } else {

                    $TempTagObject = [PSCustomObject]@{
                        'DeviceID' = @($($Device.NewDeviceWS1ID))
                        'TagName'  = $Tag.Name
                        'TagID'    = $TagID
                        'Action'   = $Action
                    }
                    $TagsToAdd += $TempTagObject
                }
            }


            # Translate to the correct tag based on the device name
            $TagName = "APPL-Deployment Devices Ending $($Device.NewDeviceName.Substring($Device.NewDeviceName.Length - 1, 1))"
            $TagID = ($AllTags | Where-Object { $_.Name -eq $TagName }).TagID

            if ($NewDeviceTagInformation.TagID -notcontains $TagID ) {
                if (($TagsToAdd.TagID -contains $TagID) -and (($TagsToAdd | Where-Object { $_.TagID -eq $TagID }).Action -eq "Add")) {
                    $($TagsToAdd | Where-Object { ($_.TagID -eq $TagID) -AND ($_.Action -eq "Add") }).DeviceID += $($Device.NewDeviceWS1ID)
                } else {
                    $TempTagObject = [PSCustomObject]@{
                        'DeviceID' = @($($Device.NewDeviceWS1ID))
                        'TagName'  = $TagName
                        'TagID'    = $TagID
                        'Action'   = "Add"
                    }
                    $TagsToAdd += $TempTagObject
                }
            } else {
                if (($TagsToAdd.TagID -contains $TagID) -and (($TagsToAdd | Where-Object { $_.TagID -eq $TagID }).Action -eq "Existing")) {
                    $($TagsToAdd | Where-Object { ($_.TagID -eq $TagID) -AND ($_.Action -eq "Existing") }).DeviceID += $($Device.NewDeviceWS1ID)
                } else {
                    $TempTagObject = [PSCustomObject]@{
                        'DeviceID' = @($($Device.NewDeviceWS1ID))
                        'TagName'  = $TagName
                        'TagID'    = $TagID
                        'Action'   = "Existing"
                    }
                    $TagsToAdd += $TempTagObject
                }
            }

        }

        $WS1Information = Initialize-WS1 -Agency $Global:VariableObject.Agency -AsPlainText
        # Sort the tags to add
        foreach ($Tag in ($TagsToAdd | Where-Object { $_.Action -eq "Add" })) {
            $Result = Invoke-TagDevice -DeviceID $($Tag.DeviceID) -TagID $Tag.TagID -WS1Information $WS1Information
            Write-Log -Message "Results for Tag $($Tag.TagID)
            TagID :: $($Tag.TagID)
            DeviceID :: $($Tag.DeviceID)
            Success :: $($Result.AcceptedItems)
            Failed :: $($Result.FailedItems)"

            if ($($Result.FailedItems) -gt 0) {
                foreach ($fault in $Result.Faults.Fault) {
                    if ($Fault.Message -eq "Tag is already associated with the device") {
                        Write-Log -Message "Tag $($Tag.TagID) already exists on $($Fault.ItemValue)"
                    } else {
                        Write-Log -Message "Errors for Tag $($Tag.TagID)
                    Device :: $($Fault.ItemValue)
                    Message :: $($Fault.Message)"
                    }
                }
            }
        }

        foreach ($Device in $Devices) {

            # Validate all tags were added that are required

            $TempTagInformation = Get-DeviceTags -OldDeviceWS1ID $($Device.DeviceWS1ID) -NewDeviceWS1ID $($Device.NewDeviceWS1ID)

            # 1 and 3
            if ($null -ne $TempTagInformation) {
                $OldDeviceTagInformation = $($TempTagInformation | Where-Object { ($_.FriendlyName -eq $($Device.DeviceName)) -AND ($_.TagID -notin $IgnoredTags.TagID) })
                $NewDeviceTagInformation = $($TempTagInformation | Where-Object { $_.FriendlyName -eq $($Device.NewDeviceName) -AND ($_.TagID -notin $IgnoredTags.TagID) })
            } else {
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET Comment = 'No information returned for $($Device.DeviceName) or $($Device.NewDeviceName) within WS1 database' WHERE DeviceName = '$($Device.DeviceName)' AND NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                Write-log -Message "No information returned for either $($Device.DeviceName) or $($Device.NewDeviceName)"
            }

            $Compare = Compare-Object -ReferenceObject $OldDeviceTagInformation.TagID -DifferenceObject $NewDeviceTagInformation.TagID
            $NextAction = ""
            if ($Compare.Count -ge 1) {
                foreach ($DifferentTag in $Compare) {
                    if (($($OldDeviceTagInformation | Where-Object { $_.TagID -eq $DifferentTag.InputObject }).Name -Notlike "APPL-Deployment Devices Ending*") -AND ($($NewDeviceTagInformation | Where-Object { $_.TagID -eq $DifferentTag.InputObject }).Name -Notlike "APPL-Deployment Devices Ending*") -AND
                    ($($OldDeviceTagInformation | Where-Object { $_.TagID -eq $DifferentTag.InputObject }).TagID -notin $IgnoredTags)) {
                        if ($DifferentTag.SideIndicator -eq "<=") {
                            Write-Log -Message "At least one tag was missed, leaving $($Device.NewDeviceName) in tagging mode" -Severity 2
                            Write-Host $DifferentTag
                            $NextAction = "Tagging"
                        } elseif ($DifferentTag.SideIndicator -eq "=>") {
                            Write-Log -Message "Additional tag ($($DifferentTag.InputObject)) detected on $($Device.NewDeviceName)"

                            if ($NextAction -ne "Tagging") {
                                $NextAction = "OG"
                            }
                        }
                    }
                }
            }

            Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET TagPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -dataSource "$($Global:VariableObject.DataSource)" -ApplicationWrite
            Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -dataSource "$($Global:VariableObject.DataSource)" -ApplicationWrite

            if ($NextAction -ne "Tagging") {
                If ($Device.ARPPhase.ToString().Length -lt 2) {
                    Write-log -Message "Moving $($Device.NewDeviceName) to ARP phase"
                    # Moving to ARP Phase
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'ARP' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -dataSource "$($Global:VariableObject.DataSource)" -ApplicationWrite
                } else {
                    Write-log -Message "Moving $($Device.NewDeviceName) to OG phase"
                    # Moving to OG Phase
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'OG' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -dataSource "$($Global:VariableObject.DataSource)" -ApplicationWrite
                }
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Start-TaggingPhase
function New-WS1APIHeader {
    param (
        [string]$APIUserName,
        [securestring]$APIPassword,
        [string]$APITenantKey,
        [string]$DefaultUseJSON = "application/json"
    )
    #Secure password
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIPassword)
    $combined = $APIUserName + ":" + [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
    $encodedString = [Convert]::ToBase64String($encoding)
    $encryptedAuthString = "Basic " + $encodedString
    $headers = @{
        "Authorization"  = $encryptedAuthString
        "aw-tenant-code" = $APITenantKey
        "Accept"         = $DefaultUseJSON
        "Content-Type"   = $DefaultUseJSON
    }
    Write-Output $headers
}

function Set-WS1APIPolicy {
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
Function Initialize-WS1 {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Initialize-WS1 -Agency 'Value'
.NOTES

#>
    Param (
        [String]$Agency,
        [switch]$AsPlainText
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if ($AsPlainText) {
            Write-Log -Message "Header :: As plain text" -Source ${CmdletName} -DebugMessage
        } else {
            if ($InvokingScriptFileName -like "$scriptDirectory*") {
                $EncryptionKeyPath = "$($InvokingScriptFileName.Replace("ps1","key"))"
            } else {
                $EncryptionKeyPath = "$scriptDirectory\$($InvokingScriptFileName.Replace("ps1","key"))"
            }

            $EncryptionKey = Get-Content -Path $EncryptionKeyPath

            Write-Log -Message "Header :: Encryption Key $EncryptionKeyPath" -Source ${CmdletName} -DebugMessage
        }
        switch ($Agency) {
            Agency2 {
                [string]$APIUserName = ""
                [String]$APIPassword = ""
                [string]$APITenantKey = ""
                [String]$BaseURI = ""
            }
            Agency1 {
                [string]$APIUserName = ""
                [String]$APIPassword = ""
                [string]$APITenantKey = ""
                [String]$BaseURI = ""
            }
            Default {
            }
        }

        [string]$APIUserName = ""
        [String]$APIPassword = ""


        Write-Log -Message "Header :: Username $APIUserName" -Source ${CmdletName} -DebugMessage
        Write-Log -Message "Header :: Password $APIPassword" -Source ${CmdletName} -DebugMessage
        Write-Log -Message "Header :: APITenantKey $APITenantKey" -Source ${CmdletName} -DebugMessage
        Write-Log -Message "Header :: BaseURI $BaseURI" -Source ${CmdletName} -DebugMessage

        # Set WS1 API Policy
        Set-WS1APIPolicy

        if ($AsPlainText) {
            $WS1Credential = [PSCustomObject]@{
                Username = $APIUserName
                Password = $APIPassword | ConvertTo-SecureString -AsPlainText -Force
            }
        } else {
            [securestring]$securestring = $APIPassword | ConvertTo-SecureString -Key $EncryptionKey
            $WS1Credential = New-Object System.Management.Automation.PsCredential($APIUserName, $securestring)
        }
        # Create Header
        $WS1Header = New-WS1APIHeader -APIUserName $WS1Credential.Username -APIPassword $WS1Credential.Password -APITenantKey $APITenantKey

        $ReturnObject = [PSCustomObject]@{
            BaseURI = $BaseURI
            Header  = $WS1Header
        }

        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#region Invoke-TagDevice
Function Invoke-TagDevice {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Invoke-TagDevice -Parameter $Value
.NOTES

#>
    Param ([string[]]$DeviceID,
        $TagID,
        $WS1Information
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        try {
            if ($DeviceID.Count -gt 1) {
                $Body = @{
                    BulkValues = @{
                        Value = $DeviceID
                    }
                }

            } else {
                $Body = @{
                    BulkValues = @{
                        Value = $DeviceID
                    }
                }
            }
            $Result = Invoke-RestMethod -Uri "$($WS1Information.BaseURI)/API/mdm/tags/$($TagID)/adddevices" -Method POST -Headers $($WS1Information.Header) -Body ($Body | ConvertTo-Json)
        } catch {
            $Result = "Error"
        }
        Write-Output -InputObject $Result

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Invoke-TagDevice


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
        [string] $database = "",
        [string] $sqlCommand = $(throw "Please specify a query."),
        [string] $Username,
        [string] $Password,
        [switch] $WS1,
        [switch] $ApplicationWrite,
        [switch] $ApplicationRead
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        if ($WS1) {
            $Username = $Global:VariableObject.ReadOnlyUsername
            $Password = $Global:VariableObject.ReadOnlyPassword
            $DataSource = $Global:VariableObject.DataSource
            $Database = $Global:VariableObject.WS1Database
        }

        if ($ApplicationWrite) {
            $Username = $Global:VariableObject.WriteUsername
            $Password = $Global:VariableObject.WritePassword
            $DataSource = $Global:VariableObject.DataSource
            $Database = $Global:VariableObject.ApplicationDatabase
        }

        if ($ApplicationRead) {
            $Username = $Global:VariableObject.ReadOnlyUsername
            $Password = $Global:VariableObject.ReadOnlyPassword
            $DataSource = $Global:VariableObject.DataSource
            $Database = $Global:VariableObject.ApplicationDatabase
        }

        if ($username) {
            $connectionString = "Server=$dataSource; Database=$database; User ID=$Username; Password=$Password;"
        } else {
            $connectionString = "Server=$dataSource; Database=$database;"
        }

        Write-Log -Message "ConnectionString: $ConnectionString" -DebugMessage
        $connection = New-Object system.data.SqlClient.SQLConnection($connectionString)
        $command = New-Object system.data.sqlclient.sqlcommand($sqlCommand, $connection)
        $connection.Open()
        Write-Log -Message "Connection Opened" -DebugMessage
        $adapter = New-Object System.Data.sqlclient.sqlDataAdapter $command
        $dataset = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $connection.Close()
        Write-Log -Message "Connection closed" -DebugMessage
        Write-Log -Message "Number of results: $($dataSet.Tables.Rows.Count)" -DebugMessage
        Write-Output -InputObject $dataSet.Tables
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Invoke-SQLCommand

#region Get-Devices
Function Get-Devices {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-Devices -Parameter $Value
.NOTES

#>
    Param ([string]$Phase,
        [string]$OldDevice,
        [string]$NewDevice
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        switch ($Phase) {
            Active { $Command = "Select * from Devices where NextStep <> 'Completed'" }
            Initial { $Command = "Select * from Devices where NextStep = 'Initial'" }
            Tagging { $Command = "Select * from Devices where NextStep = 'Tagging'" }
            ARP { $Command = "Select * from Devices where NextStep = 'ARP'" }
            LiveARP { $Command = "Select * from Devices where NextStep = 'LiveARP'" }
            OG { $Command = "Select * from Devices where NextStep = 'OG'" }
            Final { $Command = "Select * from Devices where NextStep = 'Final'" }
            Default { $Command = "Select * from Devices where (DeviceName = '$OldDevice') AND (NewDeviceName = '$NewDevice')" }
        }

        $returnObject = Invoke-SqlCommand -sqlCommand "$Command" -ApplicationRead

        Write-Output -InputObject $returnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-Devices
#region Initialize-ScriptVariables
Function Initialize-ScriptVariables {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Initialize-ScriptVariables -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        switch ($ENV:UserDomain) {
            adminsrvad { $Agency = "Agency1" }
            had { $Agency = "Agency2" }
            Default { $Agency = "Unknown" }
        }
        if (($testing -eq $true) -AND ($Agency -eq "Unknown")) { $Agency = "Testing" }
        switch ($Agency) {
            Agency2 {
                $DataSource = ""
                $ApplicationDatabase = ""
                $ApplicationTable = if ($testing -eq $true) { "DevicesDev" }else { "Devices" }
                $WS1Database = ""
                $ReadOnlyUsername = ""
                $ReadOnlyPassword = ""
                $WriteUsername = ""
                $WritePassword = ""
                $TagNamesToIgnore = @("TEMP-Profile Cleanup Script",
                    "DEV-Profile Cleanup")
            }
            Agency1 {
                $DataSource = ""
                $ApplicationDatabase = ""
                $ApplicationTable = if ($testing -eq $true) { "DevicesDev" }else { "Devices" }
                $WS1Database = ""
                $ReadOnlyUsername = ""
                $ReadOnlyPassword = ""
                $WriteUsername = ""
                $WritePassword = ""
                $TagNamesToIgnore = @("")
            }
            Testing {
                $DataSource = ""
                $ApplicationDatabase = ""
                $ApplicationTable = if ($testing -eq $true) { "DevicesDev" }else { "Devices" }
                $WS1Database = ""
                $ReadOnlyUsername = ""
                $ReadOnlyPassword = ""
                $WriteUsername = ""
                $WritePassword = ""
                $TagNamesToIgnore = @("TEMP-Profile Cleanup Script",
                    "DEV-Profile Cleanup")
            }
            Default {}
        }
        # Globally Ignored Tags
        $TagNamesToIgnore += @("")

        # Convert to SecureString
        [securestring]$secStringPassword = ConvertTo-SecureString $ReadOnlyPassword -AsPlainText -Force
        [pscredential]$ReadOnlyCredObject = New-Object System.Management.Automation.PSCredential ($ReadOnlyUsername, $secStringPassword)

        [securestring]$secStringPassword = ConvertTo-SecureString $ReadOnlyPassword -AsPlainText -Force
        [pscredential]$WriteCredObject = New-Object System.Management.Automation.PSCredential ($ReadOnlyUsername, $secStringPassword)

        $ReturnObject = [PSCustomObject]@{
            'DataSource'          = $DataSource
            'ApplicationDatabase' = $ApplicationDatabase
            'ApplicationTable'    = $ApplicationTable
            'WS1Database'         = $WS1Database
            'ReadOnlyUsername'    = $ReadOnlyUsername
            'ReadOnlyPassword'    = $ReadOnlyPassword
            'ReadOnlyCredObject'  = $ReadOnlyCredObject
            'WriteUsername'       = $WriteUsername
            'WritePassword'       = $WritePassword
            'WriteCredObject'     = $WriteCredObject
            'Agency'              = $Agency
            'TagsToIgnore'        = $TagNamesToIgnore | Where-Object { $_ }
        }

        Write-Output $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialize-ScriptVariables

#region Start-LiveARPPhase
Function Start-LiveARPPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-LiveARPPhase -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = Get-Devices -Phase "LiveARP"
Write-Log -Message "Starting Live ARP Stage. This could take a while"
        foreach ($ARPDevice in $Devices) {
            <#
     1: Check that the device is online
     2: Connect to remote registry and pull uninstall keys
     3: Write JSON file
     4: Set stage to Tagging
     #>
            if ($testing -eq $True) {
                <# TESTING
                $ARPDevice = [PSCustomObject]@{
                    DeviceName      = "Agency20037051VM02"
                    DeviceSerial    = "VMware-56 4d 72 9a 5c c1 fa 1a-01 1c 3e 35 5d 67 ac 00"
                    NewDeviceSerial = "VMware-56 4d 64 a8 c4 6e 8e 10-bd eb 10 bb 42 f4 85 40"
                    NewDeviceName   = "Agency20037051VM01"
                }#>
            }
            Write-Log -Message "Attempting to connect to $($ARPDevice.DeviceName)"
            $OnlineStatus = Test-NetConnection -ComputerName $ARPDevice.DeviceName -InformationLevel Quiet

            if ($OnlineStatus -eq $True) {

                $DeviceUninstallRegistry = Invoke-Command -ComputerName "$($ARPDevice.DeviceName)" -ScriptBlock {
                    $RegistryLocations = @(
                        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                    )
                    $JSONObject = @{
                        Programs        = @()
                        OldSerialNumber = ""
                        NewSerialNumber = ""
                    }
                    foreach ($RegistryLocation in $RegistryLocations) {
                        if ($RegistryLocation -match 'Wow6432Node') {
                            $IsWOW6432Node = $true
                        } else {
                            $IsWOW6432Node = $false
                        }

                        $UninstallItems = Get-ChildItem -Path Registry::$RegistryLocation

                        foreach ($Uninstall in $UninstallItems) {
                            if ($Uninstall.GetValue('InstallDate') -like "\d\d\d\d\d\d\d\d") {
                                $InstallDate = [datetime]::parseexact($Uninstall.GetValue('InstallDate'), 'yyyyMMdd', $null).ToString('yyyy-MM-ddTHH:mm:ss')
                            } else {
                                $InstallDate = $Uninstall.GetValue('InstallDate')
                            }
                            $UninstallJSON = [PSCustomObject]@{
                                DisplayName     = $Uninstall.GetValue('DisplayName')
                                Publisher       = $Uninstall.GetValue('Publisher')
                                DisplayVersion  = $Uninstall.GetValue('DisplayVersion')
                                ProductID       = $Uninstall.PSChildName
                                InstallDate     = $InstallDate
                                InstallLocation = $Uninstall.GetValue('InstallLocation')
                                InstallSource   = $Uninstall.GetValue('InstallSource')
                                UninstallString = $Uninstall.GetValue('UninstallString')
                                IsWOW6432Node   = $IsWOW6432Node
                            }
                            $JSONObject.Programs += $UninstallJSON
                        }


                    }
                    $ReturnObject = $JSONObject
                    Write-Output -InputObject $ReturnObject
                }

                $DeviceUninstallRegistry.OldSerialNumber = $ARPDevice.DeviceSerial
                $DeviceUninstallRegistry.NewSerialNumber = $ARPDevice.NewDeviceSerial

                $DeviceUninstallRegistry | ConvertTo-Json -Compress | Out-File -FilePath "$JSONPath\$($ARPDevice.DeviceName)-$($ARPDevice.NewDeviceName).json" -Force


                if (Test-Path "$JSONPath\$($ARPDevice.DeviceName)-$($ARPDevice.NewDeviceName).json") {
                    Write-Log -Message "JSON file created for $($ARPDevice.DeviceName)-$($ARPDevice.NewDeviceName)"
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET ARPPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($ARPDevice.NewDeviceName)'" -ApplicationWrite

                    # Moving to Tag Phase
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'Tagging' WHERE NewDeviceName = '$($ARPDevice.NewDeviceName)'" -ApplicationWrite
                } else {
                    Write-Log -Message "Error writing JSON file for $($ARPDevice.DeviceName)-$($ARPDevice.NewDeviceName)"
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET ARPPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($ARPDevice.NewDeviceName)'" -ApplicationWrite
                }
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($ARPDevice.NewDeviceName)'" -ApplicationWrite
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Start-LiveARPPhase
#region Start-ARPPhase
Function Start-ARPPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-ARPPhase -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        <#
Connect to DB
Find device
Get apps list
Create JSON
Set status back to tagging phase

#>
        $Devices = Get-Devices -Phase "ARP"

        foreach ($Device in $Devices) {


            $Command = "SELECT APP.Name, APP.Version, APP.Identifier
  FROM [interrogator].[Application] APP
  LEFT JOIN deviceApplication.Application dAPP ON dAPP.PackageID = APP.Identifier
  JOIN interrogator.ApplicationList AL ON AL.ApplicationID = APP.ApplicationID
  JOIN dbo.DeviceAttributes DAT ON AL.DeviceID = DAT.DeviceID
  WHERE Dat.DeviceID like '$($Device.DeviceWS1ID)'
  ORDER BY APP.Name"
            $DeviceARP = Invoke-SqlCommand -sqlCommand "$Command" -dataSource "$($Global:VariableObject.DataSource)" -WS1

            $JSONObject = @{
                Programs        = @()
                OldSerialNumber = ""
                NewSerialNumber = ""
            }
            foreach ($ARP in $DeviceARP) {
                $UninstallJSON = [PSCustomObject]@{
                    DisplayName     = $ARP.Name
                    Publisher       = ''
                    DisplayVersion  = $ARP.Version
                    ProductID       = $ARP.Identifier
                    InstallDate     = ''
                    InstallLocation = ''
                    InstallSource   = ''
                    UninstallString = ''
                    IsWOW6432Node   = ''
                }
                $JSONObject.Programs += $UninstallJSON
            }

            $JSONObject.OldSerialNumber = $Device.DeviceSerial
            $JSONObject.NewSerialNumber = $Device.NewDeviceSerial

            $JSONObject | ConvertTo-Json -Compress | Out-File -FilePath "$JSONPath\$($Device.DeviceName)-$($Device.NewDeviceName).json" -Force


            if (Test-Path "$JSONPath\$($Device.DeviceName)-$($Device.NewDeviceName).json") {
                Write-Log -Message "JSON file created for $($Device.DeviceName)-$($Device.NewDeviceName)"
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET ARPPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite

                # Moving to Tag Phase
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'Tagging' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
            } else {
                Write-Log -Message "Error writing JSON file for $($Device.DeviceName)-$($Device.NewDeviceName)"
                Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET ARPPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
            }
            Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
        }
    }

    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Start-ARPPhase

#region Start-OGPhase
Function Start-OGPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-OGPhase -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = Get-Devices -Phase "OG"

        foreach ($Device in $Devices) {
            $MoveOn = $false
            $Command = "Select DEV.FriendlyName, DEV.SerialNumber, DEV.DeviceID, DEV.EnrollmentStatusID, DEV.LocationGroupID
    FROM dbo.Device DEV
    WHERE (DEV.FriendlyName = '$($Device.NewDeviceName)')"

            $DeviceInformation = Invoke-SqlCommand -sqlCommand "$Command" -dataSource "$($Global:VariableObject.DataSource)" -WS1

            if ($null -ne $DeviceInformation) {
                $NewDeviceInformation = $($DeviceInformation | Where-Object { $_.FriendlyName -eq $($Device.NewDeviceName) })
            }

            if ($NewDeviceInformation.LocationGroupID -eq $Device.NewDeviceOG) {
                if ($Device.DeviceOG -eq $Device.NewDeviceOG) {
                    if ($testing -eq $True) {
                        Write-Host "OGs match for $($Device.DeviceName) and $($Device.NewDeviceName)"
                    } else {
                        Write-Log -Message "OGs match for $($Device.DeviceName)-$($Device.NewDeviceName)"
                        Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET OGPhase = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite

                        # Moving to Tag Phase
                        Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                        Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'Final' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                    }
                }
            } else {
                if ($testing -eq $True) {
                    Write-Host "Updateing OG for $($Device.NewDeviceName)"
                } else {
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NewDeviceOG = '$($NewDeviceInformation.LocationGroupID | Select-Object -Unique)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                }
            }
            Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Start-OGPhase

#region Start-FinalPhase
Function Start-FinalPhase {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Start-FinalPhase -Parameter $Value
.NOTES

#>
    Param (
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = Get-Devices -Phase "Final"

        foreach ($Device in $Devices) {
            $Filename = "$JSONPath\$($Device.DeviceName)-$($Device.NewDeviceName).json"
            $Destination = "$Archivepath\$($Device.DeviceName)-$($Device.NewDeviceName).json"
            if (Test-Path -Path $Filename) {
                if ($testing -eq $True) {
                    Write-Host "File $Filename moved to $Destination"
                } else {
                    Move-Item -Path $Filename -Destination $Destination

                    # Moving to Tag Phase
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET PreviousStep = '$($Device.NextStep)' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET NextStep = 'Completed' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite

                    Invoke-SqlCommand -sqlCommand "UPDATE $($Global:VariableObject.ApplicationTable) SET LastUpdate = '$(Get-Date -Format "yyyy-MM-dd HH:mm")' WHERE NewDeviceName = '$($Device.NewDeviceName)'" -ApplicationWrite
                }
            }
        }
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Start-FinalPhase
#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================
#region FunctionListings

<#
Phase 1: Initial
Get all devices in state 'initial' and then confirm
        1: Check to see if the 'Old' device exists in WS1 and/or SCCM
            If it exists, update the serial number of old device
            If it doesn't, notify that the device could not be found
            If a duplicate exists, notify that a duplicate exists and that will need to be fixed before it proceeds
        2: Check to see if the 'new' device already exists in WS1 and/or SCCM.
            If it exists only in WS1, update the serial number and move to the next phase.
            If it exists only in SCCM, notify and wait.
            If it doesn't exist in either, wait for it to finish imaging.
            If a duplicate exists, notify that a duplicate exists and that will need to be fixed before it proceeds

Phase 2: Tag
Get all devices in state 'tag' and then confirm
        1: Check to see that all the tags on the old device, are now on the new device
            If they are, move to the next phase
            If they aren't, tag accordingly
            Note: MGMT tags should be translated e.g. 'Devices ending in #' should be translated to the correct tag

Phase 3: ARP, Local, and AD Groups
Get the ARP of the old device, as well as the local and AD groups the old device is in
        1: Monitor for the old device to be online, when it is:
            Get the installed applications via ARP
            Get the local groups (Administrators, Remote Desktop Users)
        2: Get the AD groups that the old device is in, add them to the new device. Any group unable to be added to, notify.

Phase 4: OG
Monitor the new device for a login/change of user in WS1 to an @sa.gov.au user
        1: If the enrolled user is no longer a DXC/APCD user, confirm that the OG has been moved from the Build OG to the correct OG.

Phase 5: Final
Clean up

#>
Write-ScriptHeaderOrFooter -CmdletName "Initialising" -CmdletBoundParameters $PSBoundParameters -Header

[PSCustomObject]$Global:VariableObject = Initialize-ScriptVariables
if ($testing -ne $true) {
    switch ($mode) {
        All {
            Start-InitialPhase
            Start-TaggingPhase
            Start-ARPPhase
            Start-LiveARPPhase
            Start-OGPhase
            Start-FinalPhase
        }
        Initial { Start-InitialPhase }
        Tag { Start-TaggingPhase }
        ARP { Start-ARPPhase }
        LiveARP { Start-LiveARPPhase }
        OG { Start-OGPhase }
        Final { Start-FinalPhase }
        Default { Write-Log -Message "No mode selected. Exiting script" -Severity 3 }
    }
}

Exit-Script -ExitCode 0
#endregion
##*=============================================
##* END SCRIPT BODY
##*=============================================
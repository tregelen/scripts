<#
.SYNOPSIS
    A form used in conjunction with the MDT imaging process to copy the application suite from the old device, to the new refreshed device
.INPUTS
    None
.OUTPUTS
    Log file, location specified with variable $LogDir
.NOTES
    Version:        0.0.3
    Author:         Aaron Whittaker
    Creation Date:  14/06/2022
    Purpose/Change: Initial script development

    Version:        0.0.4
    Author:         Aaron Whittaker
    Creation Date:  22/08/2022
    Purpose/Change: Added functionality
                    Search function
                    Context menu to allow manual editing of entries
#>
##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

param(
)
#region Version
$ScriptVersion = "1.0.0" # Master.Develop.Branch

##* Do not modify section below
[string]$scriptDirectory = $PSScriptRoot
[string]$Global:InvokingScriptFileName = $PSCommandPath.Replace($scriptDirectory, "")
[Boolean]$DisableLogging = $False
[decimal]$LogMaxSize = 10
[string]$Global:ScriptSection = "Initalisation"
[string]$LogStyle = "CMTrace"
[boolean]$CompressLogs = $false
[string]$logTempFolder = "$ENV:Temp"
[string]$LogDir = "$ENV:ProgramData\Logs\Scripts"
[boolean]$LogWriteToHost = $true
[boolean]$LogDebugMessage = $false
[string]$AssemblyDirectory = "$scriptDirectory\Assembly"
[string]$ResourcesDirectory = "$scriptDirectory\Resources"
[string]$ImagesDirectory = "$ResourcesDirectory\Images"
[string]$XAMLDirectory = "$ResourcesDirectory\XAML"
[int]$MaxThreads = 10
##* Do not modify section above
if ($Testing -eq $True) {
    [string]$scriptDirectory = "C:\Users\awhittaker4\Desktop\Workstation-ImagingAdministrator"
    [string]$Global:InvokingScriptFileName = "Workstation-ImagingAdministrator.ps1"
    [string]$AssemblyDirectory = "$scriptDirectory\Assembly"
    [string]$ResourcesDirectory = "$scriptDirectory\Resources"
    [string]$ImagesDirectory = "$ResourcesDirectory\Images"
    [string]$XAMLDirectory = "$ResourcesDirectory\XAML"
}
#endregion
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings

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
#region Import-Frameworks
Function Import-Frameworks {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Import-Frameworks -Parameter $Value
.NOTES

#>
    Param ([string]$directory = $AssemblyDirectory
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        [System.Reflection.Assembly]::LoadWithPartialName('presentationframework') | Out-Null
        [System.Reflection.Assembly]::LoadFrom("$directory\MahApps.Metro.dll") | Out-Null
        #[System.Reflection.Assembly]::LoadFrom("$directory\System.Windows.Interactivity.dll") | Out-Null
        [System.Reflection.Assembly]::LoadFrom("$directory\MaterialDesignThemes.Wpf.dll") | Out-Null
        [System.Reflection.Assembly]::LoadFrom("$directory\MaterialDesignColors.dll") | Out-Null
        [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Import-Frameworks
#region Import-Form
Function Import-Form {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Import-Form -Parameter $Value
.NOTES

#>
    Param ([string]$XAMLFile = "$XAMLDirectory\$($InvokingScriptFileName.Replace(".ps1",".xaml"))"
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        try {
            [xml]$Xaml = (Get-Content "$XAMLFile")
            $Reader = New-Object System.Xml.XmlNodeReader $Xaml
            $Window = [Windows.Markup.XamlReader]::Load($Reader)
        } catch {
            Write-Log -Message "Error building Xaml data.`n$_" -Severity 3
            Exit-Script -ExitCode (Exit-Code -Message "Error building XAML")
        }

        $Xaml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Window.FindName($_.Name) -Scope Script }

        Write-Output -InputObject $Window

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Import-Form
#region Test-ADAuthentication
Function Test-ADAuthentication {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Test-ADAuthentication -Parameter $Value
.NOTES

#>
    Param ([Parameter(Mandatory)]
        [string]$User,
        [Parameter(Mandatory)]
        $Password,
        [Parameter(Mandatory = $false)]
        $Server,
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        $argumentList = New-Object -TypeName "System.Collections.ArrayList"
        $null = $argumentList.Add($contextType)
        $null = $argumentList.Add($Domain)
        if ($null -ne $Server) {
            $argumentList.Add($Server)
        }

        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $argumentList -ErrorAction SilentlyContinue
        if ($null -eq $principalContext) {
            Write-Log -Message "$Domain\$User - AD Authentication failed"
            $ReturnObject = [PSCustomObject]@{
                'Status'   = $false
                'Name'     = ""
                'Initials' = ""
            }
        }

        if ($principalContext.ValidateCredentials($User, $Password)) {
            $UserDetails = Get-ADUser -Identity "$User"
            $ReturnObject = [PSCustomObject]@{
                'Status'   = $true
                'Name'     = "$($UserDetails.Givenname) $($UserDetails.Surname)"
                'Initials' = "$($UserDetails.Givenname.Substring(0,1))$($UserDetails.Surname.Substring(0,1))"
            }

        } else {
            Write-Warning "$Domain\$User - AD Authentication failed"
            $ReturnObject = [PSCustomObject]@{
                'Status'   = $false
                'Name'     = ""
                'Initials' = ""
            }
        }

        Write-Output -InputObject $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Test-ADAuthentication
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
    Param ([string]$Agency = $Global:Agency
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        if (!$Agency) {
            switch ($ENV:UserDomain) {
                domain1 { $Agency = "Agency1" }
                domain2 { $Agency = "Agency2" }
                domain3 { $Agency = "Both" }
                Default { $Agency = "Unknown" }
            }
        }
        Write-Log -Message "Agency :: $Agency" -DebugMessage
        if ($IsTesting -eq $true) { $Agency = "Agency1" }
        switch ($Agency) {
            Agency1 {
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
                $OGList = ""
            }
            Agency2 {
                $DataSource = ""
                $ApplicationDatabase = ""
                 $ApplicationTable = if ($testing -eq $true) { "DevicesDev" }else { "Devices" }
                $WS1Database = ""
                $ReadOnlyUsername = ""
                $ReadOnlyPassword = ""
                $WriteUsername = ""
                $WritePassword = ""
                $TagNamesToIgnore = @("")
                $OGList = ""
            }
            Both {
                $ReturnObject = @()
                $Agency1Object = Initialize-ScriptVariables -Agency "Agency1"
                $Agency2Object = Initialize-ScriptVariables -Agency "Agency2"
                $ReturnObject += $Agency1Object
                $ReturnObject += $Agency2Object
            }
            Default {}
        }
        if ($Agency -ne "Both") {
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
                'OGList'              = $OGList
            }

        }
        Write-Output $ReturnObject
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Initialize-ScriptVariables
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
        [string] $Password,
        [switch] $WS1,
        [switch] $ApplicationWrite,
        [switch] $ApplicationRead,
        [string]$Agency = $Global:Agency
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        switch ($Agency) {
            Agency1 { $LocalVariableObject = $Global:VariableObject | Where-Object { $_.Agency -eq "Agency1" } }
            Agency2 { $LocalVariableObject = $Global:VariableObject | Where-Object { $_.Agency -eq "Agency2" } }
            Default { return "No agency specified" }
        }

        if ($WS1) {
            $Username = $LocalVariableObject.ReadOnlyUsername
            $Password = $LocalVariableObject.ReadOnlyPassword
            $DataSource = $LocalVariableObject.DataSource
            $Database = $LocalVariableObject.WS1Database
        }

        if ($ApplicationWrite) {
            $Username = $LocalVariableObject.WriteUsername
            $Password = $LocalVariableObject.WritePassword
            $DataSource = $LocalVariableObject.DataSource
            $Database = $LocalVariableObject.ApplicationDatabase
        }

        if ($ApplicationRead) {
            $Username = $LocalVariableObject.ReadOnlyUsername
            $Password = $LocalVariableObject.ReadOnlyPassword
            $DataSource = $LocalVariableObject.DataSource
            $Database = $LocalVariableObject.ApplicationDatabase
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
#region Add-NewDevice
Function Add-NewDevice {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Add-NewDevice -Parameter $Value
.NOTES

#>
    Param ([string]$NewDeviceName,
        [string]$NewDeviceSerial,
        [string]$OldDeviceName,
        [string]$OldDeviceSerial,
        [string]$AddedBy,
        [string]$Agency = $Global:Agency
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        Invoke-SqlCommand -sqlCommand "INSERT INTO devices (DeviceName,DeviceSerial,NewDeviceName,NewDeviceSerial,AddedBy,AddedDate,LastUpdate,NextStep) VALUES (`'$($OldDeviceName)`',`'$($OldDeviceSerial)`',`'$($NewDeviceName)`',`'$($NewDeviceSerial)`',`'$($AddedBy)`',`'$(Get-Date -Format "yyyy-MM-dd HH:mm")`',`'$(Get-Date -Format "yyyy-MM-dd HH:mm")`',`'Initial`')" -ApplicationWrite -Agency $Agency

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Add-NewDevice
#region Get-DeviceList
Function Get-DeviceList {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-DeviceList -Parameter $Value
.NOTES

#>
    Param ([string]$Agency
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $Command = "Select * from devices"
        $AllDevices = Invoke-SqlCommand -sqlCommand $Command -ApplicationRead -Agency $Agency

        Write-Output -InputObject $AllDevices
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DeviceList
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
            # TODO Work out how to display an error on the UI
            Write-log -Message "No information returned for either $($Device.DeviceName) or $($Device.NewDeviceName)"
        }

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-DeviceTags
#region Get-OGList
Function Get-OGList {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Get-OGList -Parameter $Value
.NOTES

#>
    Param ([string]$Agency
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {

        $Command = "Select * from dbo.LocationGroupPath"
        $AllOGs = Invoke-SqlCommand -sqlCommand $Command -WS1 -Agency $Agency

        Write-Output -InputObject $AllOGs
    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Get-OGList
#region Format-DeviceList
Function Format-DeviceList {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Format-DeviceList -Parameter $Value
.NOTES

#>
    Param ($DeviceList)

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Devices = @()
        switch ($Global:Filter) {
            Active { $LimitedDevices = $DeviceList | Where-Object { ($_.NextStep -notlike "*Completed*") -AND ($_.NextStep -notlike "*Removed*") } }
            Completed { $LimitedDevices = $DeviceList | Where-Object { $_.NextStep -like "*Completed*" } }
            Errors { $LimitedDevices = $DeviceList | Where-Object { ($null -notlike $_.Comment) -AND ($_.NextStep -notlike "*Removed*") } }
            Removed { $LimitedDevices = $DeviceList | Where-Object { ($_.NextStep -like "*Removed*") } }
            All { $LimitedDevices = $DeviceList }
            Default { $LimitedDevices = $DeviceList }
        }

        foreach ($device in $LimitedDevices) {
            $tempDevices = [PSCustomObject]@{
                'Old Device Name'   = $device.DeviceName
                'Old Device Serial' = $device.DeviceSerial
                'New Device Name'   = $device.NewDeviceName
                'New Device Serial' = $device.NewDeviceSerial
                'Next Step'         = $Device.NextStep
                'Last Updated'      = $Device.LastUpdate
                'Notes'             = $Device.Comment
            }
            $Devices += $tempDevices
        }

        $MainDataGrid.ItemsSource = $Devices

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Format-DeviceList
#region Update-DeviceRecord
Function Update-DeviceRecord {
    <#
.SYNOPSIS

.DESCRIPTION

.PARAMETER CmdletName

.EXAMPLE
    Update-DeviceRecord -Parameter $Value
.NOTES

#>
    Param ($Status,
        $OldDeviceName,
        $NewDeviceName,
        $DeviceID,
        $Change,
        $AddedBy
    )

    Begin {
        [string] ${CmdletName} = $MyInvocation.MyCommand.Name
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    }
    Process {
        $Command = "UPDATE devices SET NextStep = '$Status' WHERE DeviceName = '$($OldDeviceName)' AND NewDeviceName = '$($NewDeviceName)'"

        Invoke-SqlCommand -sqlCommand "$Command" -ApplicationWrite

        Invoke-SqlCommand -sqlCommand "INSERT INTO devicelogs (DeviceID,Change,AddedBy,Date) VALUES (`'$($DeviceID)`',`'$($Change)`',`'$($AddedBy)`',`'$(Get-Date -Format "yyyy-MM-dd HH:mm")`')" -ApplicationWrite

    }
    End {
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    }
}
#endregion Update-DeviceRecord
#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================

##*=============================================
##* SCRIPT BODY
##*=============================================
#region Script Body
Import-Frameworks -directory $AssemblyDirectory
$Global:VariableObject = Initialize-ScriptVariables -Agency "Both"

$LoginForm = Import-Form -XAMLFile "$XAMLDirectory\$($InvokingScriptFileName.Replace(".ps1","-Login.xaml"))"

$LoginBtnLogin.Add_Click({
        try {
            $ADAuthTest = Test-ADAuthentication -User $LoginTxtBoxUsername.Text -Password $LoginTxtBoxPassword.Password
            if ($ADAuthTest.Status -eq $true) {
                if ($null -eq $ADAuthTest.Name) {
                    $Username = $LoginTxtBoxUsername.Text
                } else {
                    $Username = $ADAuthTest.name
                }
                $Global:VariableObject | Add-Member -MemberType NoteProperty -Name "LoggedOnUserName" -Value $ADAuthTest.name
                $Global:VariableObject | Add-Member -MemberType NoteProperty -Name "LoggedOnUserInitials" -Value $ADAuthTest.Initials
                $LoginForm.Close()
            } else {
                $LoginTxtBoxPassword.Password = ""
            }
        } catch {
            $Global:VariableObject | Add-Member -MemberType NoteProperty -Name "LoggedOnUserName" -Value $LoginTxtBoxUsername.Text
            $Global:VariableObject | Add-Member -MemberType NoteProperty -Name "LoggedOnUserInitials" -Value $ADAuthTest.Initials
            $LoginForm.Close()
        }
    })

$LoginBtnCancel.Add_Click({ $LoginForm.Close(); Exit-Script })

$LoginForm.ShowDialog() | Out-Null

$MainForm = Import-Form -XAMLFile "$XAMLDirectory\$($InvokingScriptFileName.Replace(".ps1","-MainForm.xaml"))"

$MainUserChip.content = $Global:VariableObject[0].LoggedOnUserName
$MainUserChip.icon = $Global:VariableObject[0].LoggedOnUserInitials

$Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
$Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"

$Global:Filter = "Active"
switch ($env:USERDOMAIN) {
    Domain1 {
        $Global:Agency = "Agency1"
        $MainRBAgency1.IsChecked = $true
        Format-DeviceList -DeviceList $Global:DeviceListAgency1
    }
    Domain2 {
        $Global:Agency = "Agency2"
        $MainRBAgency1.IsChecked = $true
        Format-DeviceList -DeviceList $Global:DeviceListAgency1
    }
    Domain3 {
        $Global:Agency = "Agency3"
        $MainRBAgency2.IsChecked = $true
        Format-DeviceList -DeviceList $Global:DeviceListAgency2
    }
    Default {
        $Global:Agency = "Agency1"
        $MainRBAgency1.IsChecked = $true
        Format-DeviceList -DeviceList $Global:DeviceListAgency1
    }
}
$Global:OGListAgency1 = Get-OGList -Agency 'Agency1'
$Global:OGListAgency2 = Get-OGList -Agency 'Agency2'
$MainRBAgency1.Add_Click({
        $Global:Agency = "Agency1"
        if ($null -ne $Global:DeviceListAgency1) {
            Format-DeviceList -DeviceList $Global:DeviceListAgency1
        } else {
            $MainDataGrid.ItemsSource = $null
        }
        $MainDataGrid.Refresh
    })

$MainRBAgency2.Add_Click({
        $Global:Agency = "Agency2"
        if ($null -ne $Global:DeviceListAgency2) {
            Format-DeviceList -DeviceList $Global:DeviceListAgency2
        } else {
            $MainDataGrid.ItemsSource = $null
        }
        $MainDataGrid.Refresh
    })

$cmRemoveDevice.Add_Click({ $NewStatus = "Removed"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }

        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()
        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmChangeDevice.Add_Click({ Write-Host "This function is currently not available" })

$cmStatusInitial.Add_Click({
        $NewStatus = "Initial"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }

        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()
        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }

        } })

$cmStatusTagging.Add_Click({ $NewStatus = "Tagging"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()
        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmStatusARP.Add_Click({ $NewStatus = "ARP"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()

        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmStatusLiveARP.Add_Click({ $NewStatus = "Live ARP"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()

        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmStatusOG.Add_Click({ $NewStatus = "OG"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()

        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmStatusFinal.Add_Click({ $NewStatus = "Final"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()

        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {
            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$cmStatusCompleted.Add_Click({ $NewStatus = "Completed"
        $OldDeviceName = $($MainDataGrid.SelectedItem.'Old Device Name')
        $NewDeviceName = $($MainDataGrid.SelectedItem.'New Device Name')
        if ($MainRBAgency2.IsChecked -eq $true) {
            $DeviceID = ($Global:DeviceListAgency2 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        } else {
            $DeviceID = ($Global:DeviceListAgency1 | Where-Object { ($_.DeviceName -eq $OldDeviceName ) -AND ($_.NewDeviceName -eq $NewDeviceName ) }).DeviceID
        }
        $CurrentStatus = $($MainDataGrid.SelectedItem.'Next Step').Trim()

        $Change = "$CurrentStatus -> $NewStatus"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        $result = [System.Windows.Forms.MessageBox]::Show("You are about to change the record for $OldDeviceName from $CurrentStatus to $NewStatus" , "Info" , 4)
        if ($result -eq 'Yes') {

            Update-DeviceRecord -Status "$NewStatus" -OldDeviceName $OldDeviceName -NewDeviceName $NewDeviceName -DeviceID $DeviceID -Change $Change -AddedBy $Global:VariableObject[0].LoggedOnUserName

            if ($MainRBAgency2.IsChecked -eq $true) {
                $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                Format-DeviceList -DeviceList $Global:DeviceListAgency2
            } else {
                $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                Format-DeviceList -DeviceList $Global:DeviceListAgency1
            }
        } })

$MainBtnNewDevice.Add_Click({
        $NewDevice = Import-Form -XAMLFile "$XAMLDirectory\$($InvokingScriptFileName.Replace(".ps1","-NewDevice.xaml"))"
        $NewDeviceBtnAdd.Add_Click({
                Add-NewDevice -NewDeviceName $NewDeviceTxtBoxNewDeviceName.Text -NewDeviceSerial $NewDeviceTxtBoxNewDeviceSerial.Text -OldDeviceName $NewDeviceTxtBoxOldDeviceName.Text -OldDeviceSerial $NewDeviceTxtBoxOldDeviceSerial.Text -AddedBy $Global:VariableObject[0].LoggedOnUserName
                $NewDevice.Close()
                if ($MainRBAgency2.IsChecked -eq $true) {
                    $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
                    Format-DeviceList -DeviceList $Global:DeviceListAgency2
                } else {
                    $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
                    Format-DeviceList -DeviceList $Global:DeviceListAgency1
                }

            })
        $NewDeviceBtnCancel.Add_Click({ $NewDevice.Close() })
        $Async = $NewDevice.Dispatcher.InvokeAsync({
                $NewDevice.ShowDialog() | Out-Null
            })
        $Async.Wait() | Out-Null
    })

$MainBtnRefresh.Add_Click({
        $Global:DeviceListAgency1 = Get-DeviceList -Agency "Agency1"
        $Global:DeviceListAgency2 = Get-DeviceList -Agency "Agency2"
    })

$MainBtnImport.Add_Click({
        $ImportDevice = Import-Form -XAMLFile "$XAMLDirectory\$($InvokingScriptFileName.Replace(".ps1","-ImportDevice.xaml"))"
        $ImportDevicesButton.Add_Click({
                if ($ImportDevicePath.Text.Length -lt 2) {
                    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter = 'CSV (*.csv)|*.csv' }

                    $null = $FileBrowser.ShowDialog()
                    $ImportDevicePath.Text = $FileBrowser.FileName
                } else {
                    Try {
                        $TempDevices = Get-Content -Raw -Path $ImportDevicePath.Text | ConvertFrom-Csv
                        $ErrorOccured = $False
                        foreach ($TempDevice in $TempDevices) {
                            if ($TempDevice.OldDeviceName.Length -gt 1) {
                                Add-NewDevice -NewDeviceName $TempDevice.NewDeviceName -NewDeviceSerial $TempDevice.NewDeviceSerial -OldDeviceName $TempDevice.OldDeviceName -OldDeviceSerial $TempDevice.OldDeviceSerial -AddedBy $Global:VariableObject[0].LoggedOnUserName
                                $ImportListTextBlock.Text += "$($TempDevice.OldDeviceName) to $($TempDevice.NewDeviceName) added"
                            } else {
                                $ImportListTextBlock.Text = "Error importing CSV, check that the correct template was used and try again"
                                $ErrorOccured = $True
                                break
                            }
                        }
                        if ($ErrorOccured -eq $False) {
                            $ImportDevice.Close()
                        }
                    } Catch {
                        $ImportListTextBlock.Text = "Error importing CSV, check the path and try again"
                    }
                }
            })
        $ImportDevicesButtonCancel.Add_Click({ $ImportDevice.Close() })
        $Async = $ImportDevice.Dispatcher.InvokeAsync({
                $ImportDevice.ShowDialog() | Out-Null
            })
        $Async.Wait() | Out-Null
    })

$MainComboView.Add_SelectionChanged({

        switch ($Global:Agency) {
            Agency1 { $AllDevices = $Global:DeviceListAgency1 }
            Agency2 { $AllDevices = $Global:DeviceListAgency2 }
            Default { return "No agency selected" }
        }
        $Global:Filter = "$($MainComboView.SelectedItem.Content)"
        Format-DeviceList -DeviceList $AllDevices
    })

$MainDataGrid.Add_SelectionChanged({
        switch ($Global:Agency) {
            Agency1 {
                $AllDevices = $Global:DeviceListAgency1
                $AllOGs = $Global:OGListAgency1
            }
            Agency2 {
                $AllDevices = $Global:DeviceListAgency2
                $AllOGs = $Global:OGListAgency2
            }
            Default { return "No agency selected" }
        }

        $SelectedDeviceInformation = $AllDevices | Where-Object { ($_.DeviceName -eq $($MainDataGrid.SelectedItem.'Old Device Name')) -AND ($_.NewDeviceName -eq $($MainDataGrid.SelectedItem.'New Device Name')) }

        $textblockOldDeviceName.Text = $SelectedDeviceInformation.DeviceName
        $textblockOldDeviceSerial.Text = $SelectedDeviceInformation.DeviceSerial
        $textblockOldDeviceWS1ID.Text = $SelectedDeviceInformation.DeviceWS1ID
        try {
            $TempOGPath = $AllOGs | Where-Object { $_.LocationGroupID -like $SelectedDeviceInformation.DeviceOG }
            $OGPath = ($TempOGPath.LocationGroupPath).Replace("Global / Customer Buffer / ", "")
        } catch {
            $OGPath = ""
        }
        $textblockOldDeviceWS1OG.Text = $OGPath

        $textblockNewDeviceName.Text = $SelectedDeviceInformation.NewDeviceName
        $textblockNewDeviceSerial.Text = $SelectedDeviceInformation.NewDeviceSerial
        $textblockNewDeviceWS1ID.Text = $SelectedDeviceInformation.NewDeviceWS1ID
        try {
            $TempOGPath = $AllOGs | Where-Object { $_.LocationGroupID -like $SelectedDeviceInformation.NewDeviceOG }
            $OGPath = ($TempOGPath.LocationGroupPath).Replace("Global / Customer Buffer / ", "")
        } catch {
            $OGPath = ""
        }
        $textblockNewDeviceWS1OG.Text = $OGPath

        $textblockDateAdded.Text = $SelectedDeviceInformation.AddedDate
        $textblockLastUpdate.Text = $SelectedDeviceInformation.LastUpdate
        $textblockInitialPhase.Text = $SelectedDeviceInformation.InitialPhase
        $textblockTagPhase.Text = $SelectedDeviceInformation.TagPhase
        $textblockARPPhase.Text = $SelectedDeviceInformation.ARPPhase

        $textblockNotes.Text = $SelectedDeviceInformation.Comment

    })


$SearchBox.Add_TextChanged({
        switch ($Global:Agency) {
            Agency1 { $AllDevices = $Global:DeviceListAgency1 }
            Agency2 { $AllDevices = $Global:DeviceListAgency2 }
            Default { return "No agency selected" }
        }
        $Global:Filter = "$($MainComboView.SelectedItem.Content)"
        Format-DeviceList -DeviceList ($AllDevices | Where-Object { ($_.DeviceName -like "*$($SearchBox.Text)*") -OR ($_.NewDeviceName -like "*$($SearchBox.Text)*") })
    })


$MainForm.Title = "$($MainForm.Title) version $ScriptVersion"
$Async = $MainForm.Dispatcher.InvokeAsync({
        $MainForm.ShowDialog() | Out-Null
    })
$Async.Wait() | Out-Null

if ($Testing -eq $true) {
} else {
    Exit-Script -ExitCode 0
}
#endregion
##*=============================================
##* END SCRIPT BODY
##*=============================================
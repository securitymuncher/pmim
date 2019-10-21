#requires -version 3 -modules ActiveDirectory
<#
.SYNOPSIS
    This script will find users within the active directory environement with stale accounts.

.DESCRIPTION
    Powershell script to search a given OU for stale users based on the script input.

.INPUTS fileOutPath
    Path where you want to store the output files of the script.

.INPUTS moveusers
    Confirmation switch that you want to move the users. If you want to move the users, include the -MoveUsers parameter.

.INPUTS disableUsers
    Confirmation switch that you want to disable the stale users found. If you want to disable the users, include the -disableUsers parameter.

.INPUTS daysStale
    This tells the script how many days you want to use as a basis to determine if an account is stale.

.INPUTS domainCredentials
    ***Not Implemented***
    User with domain credentials to perform administrative actions. If this is not passed by default and the -Batch flag is not passed as well,
    the script will prompt the user to enter domain credentials. 

.INPUTS batch
    ***Not Implemented***
    This flag sets the script to run in a batch mode, not prompting for credentials. This will assume the scheduled task or process calling it
    has the appropiate permissions in active directory and on the machine where it is ran.

.OUTPUTS
    <What outputs will occur? Log file gots to be stored somewhere!>

.NOTES
    Version: 1.1
    Author: Patrick Lowther (PL)
    Creation Date: 2019-09-04
    Purpose: Powershell script to return a list of all stale user accounts in the Active Directory Environment, move those users to a target
             OU, and then generate a report based on the actions.
    
.EXAMPLE
    <Put some example here>

#>
param(
    [cmdletbinding()]
        [Parameter(Mandatory = $true, HelpMessage = "Path to a directory to write log files and CSVs out to.")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$fileOutPath,

        #Disable the below parameters until we flesh this all the way out
        # [Parameter(ParameterSetName="BatchSettings",Mandatory=$false)][switch]$batch = $false,
        # [Parameter(ParameterSetName="BatchSettings",Mandatory=$true)][string]$batchFile

        [Parameter(Mandatory = $true, HelpMessage = "The full distinguished name of the OU you want to search")]
        [string]$searchOU,

        [Parameter(Mandatory = $true, HelpMessage = "The full distinguished name of the Stale User OU")]
        [string]$staleUserOU,
        
        [Parameter(Mandatory = $true, HelpMessage = "The number of days to consider an account stale.")]
        [int32]$daysStales,
        
        [Parameter(Mandatory = $false, HelpMessage = "True or False. Setting this to true will move the users to the specified Stale User OU")]
        [allowNull()]
        [switch]$moveUsers=$false,

        [Parameter(Mandatory = $false, HelpMessage = "True or False. Setting this to true will disable the users.")]
        [allowNull()]
        [switch]$disableUsers=$false
        # [allowNull()]
        # [string]$domainCredentials = (Get-Credential -message "Please enter a user with Active Directory domain administration privalleges")

)

#---Script Variable Declarations---#
$timeStamp = get-date -format o | ForEach-Object {$_ -replace ":", "."}
#Report file name and extension
$baseFileName = "AD_Cleanup_Stale_Users"
$fileExt = ".csv"
#Log file name and extension
$logFileName = "Ad_Cleanup_Stale_Users_Log"
$logfileExt = ".log"
#Error Log Name and Extension
$errorLogName = "AD_Cleanup_Stale_Users_Errors"
$errorLogExt = ".log"
#File name creation Stuff
$logFile = $logfileName + "-" + $timeStamp + $logfileExt 
$fileName = $baseFileName + "-" + $timeStamp + $fileExt
$errorLogFile = $errorLogName + "-" + $timeStamp + $errorLogExt
#Where to save everything
$targetSavePath = "$fileOutPath"
$fileOutTest = "~try.01"
$fileOutPathFile = Join-Path -Path $targetSavePath -ChildPath $fileOutTest
$archivePath = Join-Path -Path $targetSavePath -ChildPath "Archive"
$archiveFiles = Join-Path -Path $targetSavePath -ChildPath "*.*"
$fullSavePN = Join-Path -Path $targetSavePath -ChildPath $fileName
$logFilePN = Join-Path -Path $targetSavePath -ChildPath $logFile
$errorLogFilePN = Join-Path -Path $targetSavePath -ChildPath $errorLogFile

#Version of the Script
$sScriptVersion = "1.1"
$ErrorActionPreference = "silentlycontinue"

#---Functions---#

#Function Requires the Active directory module
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = "Info",

        [parameter()]
        [allowNull()]
        [string]$LogFile = "C:\windows\temp\CleanStaleUsers.csv"
    )
    
    [PSCustomObject]@{
        Time = (get-date -f u)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -path $LogFile -Append -NoTypeInformation    
}

function search-staletargetOU {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [string]$sTargetOU,
    
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [int32]$sTargetDays
        )
    
    $DaysStale = 0-$sTargetDays
    Search-ADAccount -AccountInactive -DateTime((get-date).adddays($DaysStale)) -UsersOnly -SearchBase "$sTargetOU"
}

function move-staleUser {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$distinguishedName,

        [parameter(Mandatory = $true)]
        [string]$MoveToOU,

        [Parameter(Mandatory = $false)]
        [allowNull()]
        [switch]$doIIIIIT = $false
    )

    process {
        foreach ($samAccount in $distinguishedName) {
                Write-Log -Severity Info -Message "Moving $samAccount to $moveToOU" -LogFile $logFilePN
                write-output "Current Sam Account is $samAccount"
                if ($doIIIIIT -eq $false) {
                    try {
                        Write-Log -Severity Info -Message "Test Run: Moving $samAccount to stale users" -LogFile $logFilePN
                        Write-Output "Test Run: Attempting to move $samAccount"
                        Move-ADObject -Identity $samAccount -TargetPath $moveToOU -ErrorVariable $moveError -WhatIf
                        Write-Output "Test Run: Moving user would succeed!"
                    }
                    catch {
                        Write-Output "Test Run: Failed to move $samAccount"
                        Write-Output "$moveError"
                        Write-Log -Severity Info -Message "Test Run: Moving $samAccount to stale users would fail" -LogFile $logFilePN
                        Write-Log -Severity Warning -Message "Test Run: Failed to move $samAccount!" -LogFile $errorLogFilePN
                        Write-Log -Severity Warning -Message "$moveError" -LogFile $errorLogFilePN
                    }
                }
                elseif ($doIIIIIT -eq $true) {
                    try {
                        #No training wheels on this one, it's gonna move em!
                        Write-Log -Severity Info -Message "Moving $samAccount to stale users" -LogFile $logFilePN
                        Move-ADObject -Identity $samAccount -TargetPath $moveToOU -ErrorVariable $moveError
                        Write-Log -Severity Info -Message "Successful! $samAccount moved to stale users." -LogFile $logFilePN
                    }
                    catch {
                        Write-Log -Severity Warning -Message "Failed to move $samAccount!" -LogFile $errorLogFilePN
                        Write-Log -Severity Warning -Message "$moveError" -LogFile $errorLogFilePN
                    }
                }
            }
        }
    }

function disable-staleUser {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$samAccountName,

        [Parameter(Mandatory = $false)]
        [allowNull()]
        [switch]$doIIIIIT = $false
    )
    process{
        foreach ($samAccount in $samAccountName) {
            
            write-output "Current Sam Account is $samAccount"
            if ($doIIIIIT -eq $false) {
                try {
                    Write-Log -Severity Info -Message "Test Run: Disabling $samAccount due to being a stale user." -LogFile $logFilePN
                    Write-Output "Test Run: disable $samAccount."
                    Set-ADUser -Identity $samAccount -Enabled $false -ErrorVariable $disableUserError -WhatIf
                    Write-Output "Test Run: $samAccount would be successfully disabled."
                }
                catch {
                    Write-Log -Severity Warning -Message "Test run failed to disable $samAccount!" -LogFile $errorLogFilePN
                    Write-Log -Severity Warning -Message "$disableUserError" -LogFile $errorLogFilePN
                }
            }
            elseif ($doIIIIIT -eq $true) {
                try {
                    Write-Log -Severity Info -Message "Disabling $samAccount due to being a stale user." -LogFile $logFilePN
                    #No training wheels on this one, it's gonna disable accounts!
                    Write-Output "Disabling $samAccount."
                    Set-ADUser -Identity $samAccount -enabled $false -ErrorVariable $disableUserError
                    Write-Log -Severity Info -Message "Success! $samAccount is now disabled. " -LogFile $logFilePN
                }
                catch {
                    Write-Log -Severity Warning -Message "Failed to disable $samAccount!" -LogFile $errorLogFilePN
                    Write-Log -Severity Warning -Message "$disableUserError" -LogFile $errorLogFilePN
                }
            }
        }

    }

}

function invoke-userCheck {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$samAccountName
    )
    process {
        $adUserProperties = Get-ADUser -Identity $samAccountName -Properties *
        foreach ($property in $adUserProperties) {
            $lastLogin = $property.LastLogonDate
            $createdDate = $property.whenCreated
            [string]$upn = $property.UserPrincipalName
            [string]$name = $property.name
            [string]$sam = $property.samAccountName
            [string]$dept = $property.Department
            [string]$title = $property.Title
            [string]$desc = $property.DESCRIPTION
            [string]$dn = $property.distinguishedName
            # [datetime]$todayDate = get-date -f g

            #check length of $lastlogindate
            if ($null -eq $lastLogin) {
                #It's blank :(
                    #compare account creation date to current date to verify it's an older account
                    # $createdDate = $createdDate.toDateTime()
                    if ((get-date $createdDate) -gt (get-date).AddDays(-30)) {
                        #Account recently created, don't delete it
                        Write-output "Account is newer than 30 days. Skipping it for now."
                        
                        return $null
                    }
            }

            #All checks passed, glob the data together to return it to the calling user
            $currentUserDetails = [PSCustomObject]@{
                name = $name
                upn = $upn
                sam = $sam
                LastLogin = $lastLogin
                AccountCreated = $createdDate
                title = $title
                desc = $desc
                dept = $dept
                dn = $dn

                }
            
            return $currentUserDetails
        }
    }
    
}

#---Script Initializations---#
Write-Output "Initilizing script."
Write-Output "Loading Active Directory Module"
Import-Module -Name ActiveDirectory 
#---Script Work---
#try to open/write file at specified path

#DEFINE VARIABLES
$currentOU = $searchOU
$currentDays = $daysStales
$staleOU = $staleUserOU
$SOUExists = [adsi]::Exists("LDAP://$staleOU")
$TStaleOU =  [adsi]::Exists("LDAP://$currentOU")

Write-Log -Message "Starting run of invoke-pmim.ps1 version $sScriptVersion" -severity Info -logFile $logFilePN

try {
    if (-not $SOUExists) {
        Write-Log -Severity "Error" -Message "StaleOU does not exist" -LogFile $logFilePN
        Write-Output "StaleUserOU does not exist!"
        Exit
    }
}
catch {
    throw "Evaluation of stale target ou did not succeed."
}

try {
    if (-not $TStaleOU) {
        Write-Log -Severity "Error" -Message "The search OU does not exist" -LogFile $logFilePN
        Write-Output "The SearchOU does not exist!"
        Exit
    }
}
catch {
    throw "Evaluation of search ou did not succeed."
}

try {
    [io.file]::OpenWrite($fileOutPathFile).close()
    remove-item -Path $fileOutPathFile
}

catch {
    write-output  "Unable to write to a log file at $fileOutPath"
}

try {
    if (!test-path -Path $archivePath -PathType container) {
        New-Item -Path $archivePath -ItemType Container
    }
    Move-Item -path $archiveFiles -destination $archivePath -Force
}
catch {
    throw "Unable to move files to the archive directory."
    }

if (Test-Path -Path $fileOutPath -PathType Container) {

    Write-Output "Processing $currentOU for user accounts that are $currentDays days stale."
    Write-Log -Message "Processing $currentOU for user accounts that are $currentDays days stale." -Severity Info -LogFile $logFilePN
   
    $foundUsers = search-staletargetOU -sTargetOU $currentOU -sTargetDays $currentDays
        foreach ($foundUser in $foundusers) {
            $evaluatedUsers = invoke-userCheck -samAccountName $foundUser
            $evaluatedUsers | Export-Csv -Path $fullSavePN -NoTypeInformation -Append
        }
        
    Write-Output "move users: $moveUsers"
    Write-Output "disable users: $disableUsers"
$filteredUsers = Import-Csv -path $fullSavePN
    foreach ($filteredUser in $filteredUsers) {
        $currentFilteredUser = $filteredUser.sam
        $currentFilteredUserDN = $filteredUser.dn
       
        if ($disableUsers -eq $true) {
            disable-staleUser -samAccountName $currentFilteredUser -doIIIIIT
        }
        elseif ($disableUsers -eq $false) {
            disable-staleUser -samAccountName $currentFilteredUser
        }

        if ($moveUsers -eq $true) {
            move-staleUser -distinguishedName $currentFilteredUserDN -MoveToOU $staleOU -doIIIIIT
        }
        elseif ($moveUsers -eq $false) {
            move-staleUser -distinguishedName $currentFilteredUserDN -MoveToOU $staleOU
        }
    }

Write-Log -Message "Invoke-PMIM script has finished." -Severity Info -LogFile $logFilePN
}

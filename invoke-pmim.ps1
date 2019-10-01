#requires -version 3 -modules ActiveDirectory
<#
.SYNOPSIS
    This script will find users within the active directory environement with stale accounts.

.DESCRIPTION
    <fill this in later dumbo>

.INPUTS fileOutPath
    Path where you want to store the output files.

.INPUTS moveusers
    Confirmation switch that you want to move the users. If you want to move them, use -moveusers $true

.INPUTS domainCredentials
    User with domain credentials to perform administrative actions. If this is not passed by default and the -Batch flag is not passed as well,
    the script will prompt the user to enter domain credentials.

.INPUTS batch
    This flag sets the script to run in a batch mode, not prompting for credentials. This will assume the scheduled task or process calling it
    has the appropiate permissions in active directory and on the machine where it is ran.

.OUTPUTS
    <What outputs will occur? Log file gots to be stored somewhere!>

.NOTES
    Version: 1.0
    Author: Patrick Lowther (PL)
    Creation Date: 2019-09-04
    Purpose: Powershell script to return a list of all stale user accounts in the Active Directory Environment, move those users to a target
             OU, and then generate a report based on the actions.
    
.EXAMPLE
    <Put some example here>

#>
param(
    [cmdletbinding()]
        [Parameter(Mandatory = $true, HelpMessage ="Path to a directory to write log files and CSVs out to.")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$fileOutPath,

        [allowNull()]
        [switch]$moveUsers=$false,

        [allowNull()]
        [switch]$batch = $false

        # [allowNull()]
        # [string]$domainCredentials = (Get-Credential -message "Please enter a user with Active Directory domain administration privalleges")

)

#---User Defined Variables---#

# This is a multidimensional array with the first element being the organizational unit you want to set as your search base. The second element is the number of days stale. This
# is expecting the OU in the fully distinguished name format.

$searchBaseOUs = @("OU=Example1,DC=CONTOSO,DC=COM",30), @("OU=Example2,DC=CONTOSO,DC=COM",90), @("OU=CONTOSO Users,DC=CONTOSO,DC=COM",45), 
        @("OU=Example3,DC=CONTOSO,DC=COM",30), @("OU=Example4,DC=CONTOSO,DC=COM",30), @("OU=Example5,DC=CONTOSO,DC=COM",30),
        @("OU=Example6,DC=CONTOSO,DC=COM",30), @("OU=Example7,DC=CONTOSO,DC=COM",30)

# This is the fully distinguished named for the target organizational unit where stale user accounts will be moved.

$staleUserOU = "OU=Stale Accounts,DC=CONTOSO,DC=com"

#---Script Initializations---#

Import-Module -Name ActiveDirectory 


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
$archivePath = $targetSavePath + "Archive\"
$archiveFiles = $targetSavePath + "\*.*"
$fullSavePN = Join-Path -Path $targetSavePath -ChildPath $fileName
$logFilePN = Join-Path -Path $targetSavePath -ChildPath $logFile
$errorLogFilePN = Join-Path -Path $targetSavePath -ChildPath $errorLogFile

#Version of the Script
$sScriptVersion = "1.0"
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
    $sTargetOU = $sTargetOU.Replace(":",",")
    $DaysStale = 0-$sTargetDays
    Search-ADAccount -AccountInactive -DateTime((get-date).adddays($DaysStale)) -UsersOnly -SearchBase "$sTargetOU"
}

function move-staleUser {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$distinguishedName,
        [allowNull()]
        [switch]$doIIIIIT = $false
    )
    process{
        foreach ($samAccount in $distinguishedName) {
            Write-Log -Severity Info -Message "Moving $samAccount to stale users" -LogFile $logFilePN
            write-output "Current Sam Account is $samAccount"
            if ($doIIIIIT -eq $false) {
                try {
                    Write-Log -Severity Info -Message "Test Run: Moving $samAccount to stale users" -LogFile $logFilePN
                    Write-Output "Test Run: Attempting to move $samAccount"
                    Move-ADObject -Identity $samAccount -TargetPath $staleUserOU -ErrorVariable $moveError -WhatIf
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
                    Move-ADObject -Identity $samAccount -TargetPath $staleUserOU -ErrorVariable $moveError
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

#---Script Work---
#try to open/write file at specified path
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

Write-Log -Message "Starting run of invoke-pmim.ps1 version $sScriptVersion" -severity Info -logFile $logFilePN
foreach ($searchBase in $searchBaseOUs) {
    $currentOU = $searchbase[0]
    $currentDays = $searchbase[1]

    Write-Output "Processing $currentOU for user accounts that are $currentDays days stale."
    Write-Log -Message "Processing $currentOU for user accounts that are $currentDays days stale." -Severity Info -LogFile $logFilePN
   
    $foundUsers = search-staletargetOU -sTargetOU $currentOU -sTargetDays $currentDays
        foreach ($foundUser in $foundusers) {
            $evaluatedUsers = invoke-userCheck -samAccountName $foundUser
            $evaluatedUsers | Export-Csv -Path $fullSavePN -NoTypeInformation -Append
        }
        
  #search-staletargetOU -sTargetOU $currentOU -sTargetDays $currentDays | move-staleUser
    #write-Host "Searchbase: " $searchbase[0]
    #Write-Host "Days Stale: " $searchBase[1]
    }
$filteredUsers = Import-Csv -path $fullSavePN
    foreach ($filteredUser in $filteredUsers) {
        $currentFilteredUser = $filteredUser.sam
        $currentFilteredUserDN = $filteredUser.dn
        disable-staleUser -samAccountName $currentFilteredUser
        move-staleUser -distinguishedName $currentFilteredUserDN
    }

Write-Log -Message "Invoke-PMIM script has finished." -Severity Info -LogFile $logFilePN
}

<#
.SYNOPSIS
    Resets Domain service account passwords to the current one from a KeePass database.

.DESCRIPTION
    This script provides the capability to change any domain service account password to the current associated password from KeePass, on all reachable servers/services.

.EXAMPLES
    Set-ServiceAccountPasswordsFromKeePass.ps1

    Search default OU ( "OU=Servers, DC=ACME, DC=COM" ) and reset all found service accounts to password in KeePass. Will not affect if account is not found in KeePass.

.EXAMPLES
    .\Set-ServiceAccountPasswordsFromKeePass.ps1 -Q

    Search specified OU ( "OU=Q, OU=Servers, DC=ACME, DC=COM" ) and reset all found service accounts to password in KeePass. Will not affect if account is not found in KeePass.

.EXAMPLES
    .\Set-ServiceAccountPasswordsFromKeePass.ps1 Server01, Server02

    Search specified servers ( Server01 and Server02 ) and reset all found service accounts to password in KeePass. Will not affect if account is not found in KeePass.

.PARAMETER S
    Add S Server OU.

    OU=S,OU=Servers,DC=ACME, DC=COM

.PARAMETER K
    Add K Server OU.

    OU=K,OU=Servers,DC=ACME, DC=COM

.PARAMETER W
    Add W Server OU.

    OU=W,OU=Servers,DC=ACME, DC=COM

.PARAMETER H
    Add H Server OU.

    OU=H,OU=Servers,DC=ACME, DC=COM

.PARAMETER Q
    Add Q Server OU.

    OU=Q, OU=Servers, DC=ACME, DC=COM

.NOTES
    Author: Jeremy DeWitt aka JBear
    Date: 2017-04-05
    Updated: 2017-05-12
        Version 1.1:

        - Fixed multiple bugs that were clearing KeePass Master Password too soon.
        - Fixed bug that wasn't allowing restart of remote services.
        - Fixed placement of parameters.
        - Fixed error handling and output returns.
        - Fixed error that was clearing out the array of Secure Service Account Information before setting passwords.
        - Fixed detection output to show server, accounts found, and services.
        - Removed main wrapper function.
        - Added ability to supply individual or, multiple servers to pipeline to override an OU search.
        - Improved error checking.
#>

param(

    #Ability to supply a single server or, multiple server names
    [parameter(ValueFromPipeline=$true)]
    [String[]]$ServerName,
    [Switch]$S,
    [Switch]$K,
    [Switch]$W,
    [Switch]$H,
    [Switch]$Q
)

    function Get-ServiceAccounts {
    <#
    .SYNOPSIS
    Retrieve all Non-Standard Service account information from specified servers.

    .DESCRIPTION
    Retrieve all Non-Standard Service account information from specified servers. Retrieves server name, service, and service account.
    #>

    Try {

        Import-Module ActiveDirectory -ErrorAction Stop
    }

    Catch {

        Write-Host -ForegroundColor Yellow "`nUnable to load Active Directory Module, it is required to run this script. Please, install RSAT and configure this server properly."
        Break
    }

    #S server OU switch
    if($S) {

        $SearchOU += "OU=S,OU=Servers,DC=ACME, DC=COM" 
    }

    #K OU switch
    if($K) {

        $SearchOU += "OU=K,OU=Servers,DC=ACME, DC=COM"
    }

    #W server OU switch
    if($W) {

        $SearchOU += "OU=W,OU=Servers,DC=ACME, DC=COM" 
    }

    #H server OU switch
    if($H) {

        $SearchOU += "OU=H,OU=Servers,DC=ACME, DC=COM"
    }

    #Q server OU switch
    if($Q) {

        $SearchOU += "OU=Q, OU=Servers, DC=ACME, DC=COM"
    }

    #If no OU switches are present, use parent Servers OU for array
    if(!($S.IsPresent -or $K.IsPresent -or $W.IsPresent -or $H.IsPresent -or $Q.IsPresent)){
    
        if([string]::IsNullOrWhiteSpace($Names)) { 
            #Set $SearchOU to parent server OU
            $SearchOU = "OU=Servers,DC=ACME, DC=COM"
        }
    }

    Write-Host "`nScanning service information:"

    if([String]::IsNullOrWhiteSpace($ServerName)) {
    
        #Process each item in $SearchOU
        foreach($OU in $SearchOU) {

            Write-Progress -Activity "Retrieving information from selected servers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SearchOU.count) * 100) + "%") -CurrentOperation "Processing $($OU)..." -PercentComplete ((($j++) / $SearchOU.count) * 100)
    
            #OU can't be $null or whitespace
            if(!([string]::IsNullOrWhiteSpace($OU))) {
                
                Try {

                    #Retrieve all server names from $OU
                    $ServerName = (Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter * -ErrorAction Stop).Name 
                }

                Catch {
                
                    #OU values are incorrect or unreachable
                    Write-Host -ForegroundColor Yellow "Incorrect OU(s)."
                    
                }
            }
        }
    }

    foreach ($S in $ServerName) {

        Write-Host "$S"
    }

    $i=0
    $j=0

        #Create function
        function Get-Accounts {

            #Process each item in $ServerList
            foreach ($Server in $ServerName) {
        
                #Progress bar/completion percentage of all items in $ServerList
                Write-Progress -Activity "Creating job for $Server to query Local Services..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ServerName.count) * 100) + "%") -CurrentOperation "Processing $($Server)..." -PercentComplete ((($j++) / $ServerName.count) * 100)

                #Only continue if able to ping
                if(Test-Connection -Quiet -Count 1 $Server) {

                    #Creat job to run parallel
                    Start-Job -ScriptBlock { param($Server)

                        <# Query each computer
                        Note: Get-CIMInstance -ComputerName $Server -ClassName Win32_Service -ErrorAction SilentlyContinue 
                        won't currently work with out of date PowerShell on some servers; change to CIM if your entire environment is running POSH v3 or higher #>
                        $WMI = (Get-WmiObject -ComputerName $Server -Class Win32_Service -ErrorAction SilentlyContinue | 

                        #Filter out the standard service accounts
                        Where-Object -FilterScript {$_.StartName -ne "LocalSystem"}                  |
                        Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\NetworkService"}  | 
                        Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\LocalService"}    |
                        Where-Object -FilterScript {$_.StartName -ne "Local System"}                 |
                        Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Local Service"}   |
                        Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Network Service"} |
                        Where-Object -FilterScript {$_.StartName -notlike "NT SERVICE\*"} |
                        Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\system"})

                        foreach($Obj in $WMI) {
                        
                            [pscustomobject] @{

                                StartName    = $Obj.StartName
                                Name         = $Obj.Name
                                DisplayName  = $Obj.DisplayName
                                StartMode    = $Obj.StartMode
                                SystemName   = $Obj.SystemName
                            }
                        }          
                    } -ArgumentList $Server
                }
            }
        }

    Get-Accounts | Receive-Job -Wait -AutoRemoveJob
    } 

    function OutputDetected {

        $TestPath = $FoundAccounts

        Write-Host "`nService Accounts detected:"

        if([String]::IsNullOrEmpty($TestPath)) {
            
            Write-Host -ForegroundColor Yellow "`nNotice: No service accounts detected."
            Break
        }

        else {
       
            foreach($Found in $FoundAccounts) {
        
                $Found.SystemName + " | " + $Found.DisplayName + " | " + (Split-Path -Path $Found.StartName -Leaf)
            }
        }
    }

    function LoadKeePass {

        #Path to KeePass
        $PathToKeePassFolder = "C:\Program Files (x86)\KeePass"

        #Load all KeePass .NET binaries in the folder
        (Get-ChildItem -Recurse $PathToKeePassFolder| Where {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | Out-Null
    }

    function Find-PasswordInKeePassDBUsingPassword {

    <#
    .SYNOPSIS
    Access KeePass Master DB; required to enter proper password to continue.

    .DESCRIPTION
    Access KeePass Master DB; required to enter proper password to continue.
    #>

        [CmdletBinding()]
        [OutputType([String[]])]

        Param(
        
            #KeePass Database Path
            $PathToDB = "C:\Program Files (x86)\KeePass\EnterpriseServicesSchoolMaster.kdbx"   
        )

        Do {

            While($True) {

                #KeePass Database Master Password; secure-string            
                $MasterPasswordDB = (Read-Host -Prompt "KeePass Master Password" -AsSecureString)

                #Service Account Names
                $ServiceAccounts = Split-Path -Path $FoundAccounts.StartName -Leaf | Select -Unique

                Try {

                    foreach($Account in $ServiceAccounts) {

                        #Pass Secure String to BinaryString
                        $BSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($MasterPasswordDB)

                        #Create KeyPass object
                        $PwDatabase = New-Object KeePassLib.PwDatabase

                        #Create composite key
                        $m_pKey = New-Object KeePassLib.Keys.CompositeKey

                        #Pass Binary String
                        $Password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)

                        #Access database with given Master Password
                        $m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($Password)))

                        #Remove secure variables from memory
                        Remove-Variable Password

                        #Zero out Binary String
                        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

                        #Connect to KeePass Database
                        $m_ioInfo = New-Object KeePassLib.Serialization.IOConnectionInfo

                        #Set Database path
                        $m_ioInfo.Path = $PathToDB

                        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

                        #Open KeePass Database
                        $PwDatabase.Open($m_ioInfo,$m_pKey,$IStatusLogger)

                        #Retrieve all objects from RootGroup
                        $pwItems = $PwDatabase.RootGroup.GetObjects($true, $true)

                        foreach($pwItem in $pwItems) {

                            #Accounts that match items from $Account
                            if ($pwItem.Strings.ReadSafe("UserName") -like "*$Account*") {
                        
                                #Secure Account Data
                                [pscustomobject] @{

                                    Title = ConvertTo-SecureString $pwItem.Strings.ReadSafe("Title") -AsPlainText -Force
                                    Name  = ConvertTo-SecureString $pwItem.Strings.ReadSafe("UserName") -AsPlainText -Force
                                    PW    = ConvertTo-SecureString $pwItem.Strings.ReadSafe("Password") -AsPlainText -Force
                                }        
                            }
                        }

                        #Close KeePass Database
                        $PwDatabase.Close()
                    }
            
                    #Set $CorrectDBPass to break Do{} loop
                    $CorrectDBPass = $True
                    Break;
                }

                Catch {

                    #Zero out Binary String
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
                    #Incorrect Master DB Password entry will throw you back to re-enter a password, and throw this error
                    Write-Host -ForegroundColor Yellow "An error ocurred. The Master Password you entered is incorrect. Please try again."       
                }
            }
        }

    Until($CorrectDBPass -eq $True)
    }

    function Set-AccountPassword {

    <#
    .SYNOPSIS
    Automatically set service account passwords on remote servers, based on the current KeePass Database Account information.

    .DESCRIPTION
    Automatically set service account passwords on remote servers, based on the current KeePass Database Account information.
    #>

        #Find a way to set credentials for multiple accounts, pass them to services based on account name.
        [CmdletBinding(SupportsShouldProcess=$true)]

        param(
        
            $ServiceInfo = $FoundAccounts,
            $ServerName = $ServiceInfo.SystemName,
            $ServiceCredential = $CurrentAccountData     
        )
       
        function Set-ServiceCredential {
        [CmdletBinding(SupportsShouldProcess=$true)]

            param(
        
            [Parameter(ValueFromPipeline=$true,Position=0)]
            [string]$AccountName,

            [Parameter(ValueFromPipeline=$true,Position=1)]
            [string]$Server,
         
            [Parameter(ValueFromPipeline=$true,Position=2)]
            [string]$Pass       
        )

            #Filter by Name
            $wmiFilter = "Name='{0}'" -f $Service.Name

            #Parameters for Get-WMIObject
            $params = @{

                "Class" = "Win32_Service"
                "ComputerName" = $Server
                "Filter" = $wmiFilter
                "ErrorAction" = "Stop"
            }

            #Check for services
            $WMIobj = Get-WmiObject @params

            $ServiceName = $Service.Name 

            #Set credentials on specified $Service.Name
            if($PSCmdlet.ShouldProcess("Service '$Service.Name' on '$Server'","Set credentials")) {

                #See https://msdn.microsoft.com/en-us/library/aa384901.aspx
                $returnValue = ($WMIobj.Change($null,                  #DisplayName
                $null,                                               #PathName
                $null,                                               #ServiceType
                $null,                                               #ErrorControl
                $null,                                               #StartMode
                $null,                                               #DesktopInteract
                $AccountName,                                        #StartName
                $Pass,                                               #StartPassword
                $null,                                               #LoadOrderGroup
                $null,                                               #LoadOrderGroupDependencies
                $null)).ReturnValue                                  #ServiceDependencies
                $errorMessage = "Error setting [$AccountName] credentials for service [$ServiceName] on [$Server]"

                #Remove value
                Remove-Variable Pass

                #Error codes
                switch($returnValue) {

                    0  { Write-Output "`nSetting [$AccountName] credentials for service [$ServiceName] on [$Server]" }
                    1  { Write-Error "`n$errorMessage - Not Supported" }
                    2  { Write-Error "`n$errorMessage - Access Denied" }
                    3  { Write-Error "`n$errorMessage - Dependent Services Running" }
                    4  { Write-Error "`n$errorMessage - Invalid Service Control" }
                    5  { Write-Error "`n$errorMessage - Service Cannot Accept Control" }
                    6  { Write-Error "`n$errorMessage - Service Not Active" }
                    7  { Write-Error "`n$errorMessage - Service Request timeout" }
                    8  { Write-Error "`n$errorMessage - Unknown Failure" }
                    9  { Write-Error "`n$errorMessage - Path Not Found" }
                    10 { Write-Error "`n$errorMessage - Service Already Stopped" }
                    11 { Write-Error "`n$errorMessage - Service Database Locked" }
                    12 { Write-Error "`n$errorMessage - Service Dependency Deleted" }
                    13 { Write-Error "`n$errorMessage - Service Dependency Failure" }
                    14 { Write-Error "`n$errorMessage - Service Disabled" }
                    15 { Write-Error "`n$errorMessage - Service Logon Failed" }
                    16 { Write-Error "`n$errorMessage - Service Marked For Deletion" }
                    17 { Write-Error "`n$errorMessage - Service No Thread" }
                    18 { Write-Error "`n$errorMessage - Status Circular Dependency" }
                    19 { Write-Error "`n$errorMessage - Status Duplicate Name" }
                    20 { Write-Error "`n$errorMessage - Status Invalid Name" }
                    21 { Write-Error "`n$errorMessage - Status Invalid Parameter" }
                    22 { Write-Error "`n$errorMessage - Status Invalid Service Account" }
                    23 { Write-Error "`n$errorMessage - Status Service Exists" }
                    24 { Write-Error "`n$errorMessage - Service Already Paused" }
                }

                #Remove value
                Remove-Variable AccountName
            }
        }

        foreach($Server in $ServerName) {

            foreach($Service in $ServiceInfo) {

                #If matches; continue
                if($Service.SystemName -eq $Server) {
            
                    foreach($Credential in $ServiceCredential) {
                                       
                        #Convert Secure Name String to Binary                   
                        $nBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($Credential.Name)) 

                        #Convert Binary to String
                        $nString = [system.runtime.interopservices.marshal]::PtrToStringAuto($nBSTR)   
                    
                        #Get leaf to match account values
                        $Leaf = Split-Path -Path $Service.StartName -Leaf 
                                         
                        #If contains
                        if($Leaf -eq "$nString") {
                    
                            #Convert Secure PW String to Binary
                            $pBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($Credential.PW))
                    
                            #Convert Binary to String 
                            $pString = [system.runtime.interopservices.marshal]::PtrToStringAuto($pBSTR)
                    
                            #Clear Binary Strings to avoid a potential secondary conversion
                            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($nBSTR) 
                            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)    
                                           
                            #Call function to set new password        
                            Set-ServiceCredential $Service.Startname $Server $pString
                        
                            Remove-Variable pString
                     
                            Try {
                            
                                $ServiceName = $Service.Name    

                                #Restart service
                                Invoke-Command -ComputerName $Server {
                                param($Service, $ServiceName)

                                    Restart-Service -DisplayName $Service.DisplayName -ErrorAction Stop                    
                                    Write-Output "$ServiceName restart successful." -OutVariable $Return
                                } -ArgumentList $Service, $ServiceName
                            }

                            Catch {
                            
                                $ServiceName = $Service.Name

                                Write-Host -ForegroundColor Red "$ServiceName restart failed. Please ensure the correct password is listed in KeePass for the associated account. Check services manually"
                            }
                        }
                    
                        else {
                        
                            Continue
                        }
                    }
                }

                else {
                
                    Continue                
                }
            }
        }
    }

#Call function and store output
$FoundAccounts = Get-ServiceAccounts

#Call function
OutputDetected

#Call function
LoadKeePass

#Call function and store data
$CurrentAccountData = Find-PasswordInKeePassDBUsingPassword

#Call function
Set-AccountPassword

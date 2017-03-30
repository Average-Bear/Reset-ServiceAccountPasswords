<#
Final goal: Ability to reset all service account passwords, on all servers, for all services. New passwords and account information will
be based off of information from KeePass Database. This script could potentially be adjusted to work with a different software or a different input method, if preferred.

Current goals: 
      
- Clear any variables containing secure information in cleartext after new passwords have been set.
- Complete all documentation.
- Search for KeePass.exe location, then feed the filepath instead of hardcoding a location.

Achieved goals: 
- Access KeePass Master DB and retrieve all accounts information as a secure string.
- Bring secure string back to Binary, then to string again because change method doesn't accept Secure Strings.
- Integrated Get-NonStandardServiceAccounts output. 
- Used Get-NonStandarServiceAccounts information from server and passed it into the account search within the KeePass Database.
- Included a Do{ While{}} loop to handle mistyped Master DB Password.

Notes: This script is in beta testing at the current moment. Proper variables aren't set within several different functions; as I am 
testing individual functionality before integrating them with each other.

Feel free to add or adjust anything that you think could be helpful but, please review the current goals before implementing changes and submitting to me. 
#>

function Get-ServiceAccounts {
<#
.SYNOPOSIS
Change values of switches (if desired) and change default parent OU on line 62.

Add appropriate switch to line 150 if you wish to change domain or OU (defaults to OU=Computers,DC=acme,DC=com OU)
#>

Param(
[parameter(ValueFromPipeline=$true)]
    [String[]]$Names,
    [Switch]$S,
    [Switch]$K,
    [Switch]$W,
    [Switch]$H,
    [Switch]$ConvertToHTML
)

Try {

    Import-Module ActiveDirectory -ErrorAction Stop
}

Catch {

    Write-Host -ForegroundColor Yellow "`nUnable to load Active Directory Module is required to run this script. Please, install RSAT and configure this server properly."
    Break
}

#Format today's date
$LogDate = (Get-Date -format yyyyMMdd)

#S server OU switch
if($S) {

    $SearchOU += "OU=S,OU=Computers,DC=acme,DC=com"
}

#K server OU switch
if($K) {

    $SearchOU += "OU=K,OU=Computers,DC=acme,DC=com"
}

#W server OU switch
if($W) {

    $SearchOU += "OU=W,OU=Computers,DC=acme,DC=com" 
}

#H server OU switch
if($H) {

    $SearchOU += "OU=H,OU=Computers,DC=acme,DC=com"
}

#If no OU switches are present, use parent 05_Servers OU for array
if(!($S.IsPresent -or $K.IsPresent -or $W.IsPresent -or $H.IsPresent)){
    
    if([string]::IsNullOrWhiteSpace($Names)) { 
        #Set $SearchOU to parent server OU
        $SearchOU = "OU=Computers,DC=acme,DC=com"
    }
}

Write-Host "`nRetrieving server information from:"

if([String]::IsNullOrWhiteSpace($Names)) {
    
    #Process each item in $SearchOU
    foreach($OU in $SearchOU) {

        Write-Progress -Activity "Retrieving information from selected servers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SearchOU.count) * 100) + "%") -CurrentOperation "Processing $($OU)..." -PercentComplete ((($j++) / $SearchOU.count) * 100)
    
        #OU can't be $null or whitespace
        if(!([string]::IsNullOrWhiteSpace($OU))) {
    
            #Retrieve all server names from $OU
            $Names = (Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter *).Name

            #Add server names to $ComputerList Array
            $ComputerList += $Names
        }
    }
}

else {

    $ComputerList += $Names
}

foreach ($C in $ComputerList) {

    Write-Host "$C"
}

$i=0
$j=0

#Create function
function Get-Accounts {

    #Process each item in $ComputerList
    foreach ($Computer in $ComputerList) {
        
        #Progress bar/completion percentage of all items in $ComputerList
        Write-Progress -Activity "Creating job for $Computer to query Local Services..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerList.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerList.count) * 100)

        #Only continue if able to ping
        if(Test-Connection -Quiet -Count 1 $Computer) {

            #Creat job to run parallel
            Start-Job -ScriptBlock { param($Computer)

                <# Query each computer
                Note: Get-CIMInstance -ComputerName $Computer -ClassName Win32_Service -ErrorAction SilentlyContinue 
                won't currently work with out of date PowerShell on some servers #>
                $WMI = (Get-WmiObject -ComputerName $Computer -Class Win32_Service -ErrorAction SilentlyContinue | 

                #Filter out the standard service accounts
                Where-Object -FilterScript {$_.StartName -ne "LocalSystem"}                  |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\NetworkService"}  | 
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\LocalService"}    |
                Where-Object -FilterScript {$_.StartName -ne "Local System"}                 |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Local Service"}   |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Network Service"} |
                Where-Object -FilterScript {$_.StartName -notlike "NT SERVICE\MSSQL*"} |
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
                
            } -ArgumentList $Computer
        }
    }
}

    Get-Accounts | Wait-Job | Receive-Job
} 

$FoundAccounts = Get-ServiceAccounts -School

$PathToKeePassFolder = "C:\Program Files (x86)\KeePass"

#Load all KeePass .NET binaries in the folder
(Get-ChildItem -Recurse $PathToKeePassFolder| Where {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | Out-Null

function Find-PasswordInKeePassDBUsingPassword {

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
        $ServiceAccounts = Split-Path -Path $FoundAccounts.StartName -Leaf
    
        #Pass Secure String to BinaryString
        $BSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($MasterPasswordDB)

        #Pass Binary String
        $Password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)

        #Empty array for later use in script
        $CurrentAccountData=@()

        Try {

            foreach($Account in $ServiceAccounts) {

                #Create KeyPass object
                $PwDatabase = New-Object KeePassLib.PwDatabase

                #Create composite key
                $m_pKey = New-Object KeePassLib.Keys.CompositeKey

                #Access database with given Master Password
                $m_pKey.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($Password)))

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
            
                        $SecureAccountData = [pscustomobject] @{

                            Title = ConvertTo-SecureString $pwItem.Strings.ReadSafe("Title") -AsPlainText -Force
                            Name  = ConvertTo-SecureString $pwItem.Strings.ReadSafe("UserName") -AsPlainText -Force
                            PW    = ConvertTo-SecureString $pwItem.Strings.ReadSafe("Password") -AsPlainText -Force
                        }

                        $tBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.Title))                   
                        $nBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.Name))    
                        $pBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.PW))
                    
                        $tString = [system.runtime.interopservices.marshal]::PtrToStringAuto($tBSTR)      
                        $nString = [system.runtime.interopservices.marshal]::PtrToStringAuto($nBSTR)
                        $pString = [system.runtime.interopservices.marshal]::PtrToStringAuto($pBSTR) 
                    
                    
                        $CurrentAccountData += [pscustomobject] @{
                        
                          Title =  $tString
                          Name =  $nString
                          PW =  $pString

                        }          
                    }
                }

                #Close KeePass Database
                $PwDatabase.Close()
            }
            
            $CorrectDBPass = $True
            Break;
        }

        Catch {

            Write-Host -ForegroundColor Yellow "An error ocurred. The Master Password you entered is incorrect. Please try again."
        
        }
    }
}

Until($CorrectDBPass -eq $True)


    #Zero out Binary String
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    #Remove secure variables from memory
    Remove-Variable Password

    #Generate KeePass account output
    $CurrentAccountData
}

$Data = Find-PasswordInKeePassDBUsingPassword | Select -Unique * 

#Used for testing output purposes (uncomment if you want to ensure you're pulling the proper data)
#$Data 

function Set-ServiceAccountPassword {

    #Find a way to set credentials for multiple accounts, pass them to services based on account name.
    [CmdletBinding(SupportsShouldProcess=$true)]

    param(
        $ServiceCredential=$Data,
        $ComputerName = $FoundAccounts.SystemName,
        $ServiceName = $FoundAccounts.Name
    )
       
    function Set-ServiceCredential {

        $wmiFilter = "Name='{0}' OR DisplayName='{0}'" -f $Service
        $params = @{

          "Class" = "Win32_Service"
          "ComputerName" = $Computer
          "Filter" = $wmiFilter
          "ErrorAction" = "Stop"
        }

        $WMIobj = Get-WmiObject @params


        if($PSCmdlet.ShouldProcess("Service '$Service' on '$Computer'","Set credentials")) {

          # See https://msdn.microsoft.com/en-us/library/aa384901.aspx
          $returnValue = ($WMIobj.Change($null,                  # DisplayName
            $null,                                               # PathName
            $null,                                               # ServiceType
            $null,                                               # ErrorControl
            $null,                                               # StartMode
            $null,                                               # DesktopInteract
            $Credential.Name,                                    # StartName
            $Credential.PW,                                      # StartPassword
            $null,                                               # LoadOrderGroup
            $null,                                               # LoadOrderGroupDependencies
            $null)).ReturnValue                                  # ServiceDependencies
          $errorMessage = "Error setting credentials for service '$Service' on '$Computer'"

            switch($returnValue) {

                0  { Write-Verbose "Set credentials for service '$Service' on '$Computer'" }
                1  { Write-Error "$errorMessage - Not Supported" }
                2  { Write-Error "$errorMessage - Access Denied" }
                3  { Write-Error "$errorMessage - Dependent Services Running" }
                4  { Write-Error "$errorMessage - Invalid Service Control" }
                5  { Write-Error "$errorMessage - Service Cannot Accept Control" }
                6  { Write-Error "$errorMessage - Service Not Active" }
                7  { Write-Error "$errorMessage - Service Request timeout" }
                8  { Write-Error "$errorMessage - Unknown Failure" }
                9  { Write-Error "$errorMessage - Path Not Found" }
                10 { Write-Error "$errorMessage - Service Already Stopped" }
                11 { Write-Error "$errorMessage - Service Database Locked" }
                12 { Write-Error "$errorMessage - Service Dependency Deleted" }
                13 { Write-Error "$errorMessage - Service Dependency Failure" }
                14 { Write-Error "$errorMessage - Service Disabled" }
                15 { Write-Error "$errorMessage - Service Logon Failed" }
                16 { Write-Error "$errorMessage - Service Marked For Deletion" }
                17 { Write-Error "$errorMessage - Service No Thread" }
                18 { Write-Error "$errorMessage - Status Circular Dependency" }
                19 { Write-Error "$errorMessage - Status Duplicate Name" }
                20 { Write-Error "$errorMessage - Status Invalid Name" }
                21 { Write-Error "$errorMessage - Status Invalid Parameter" }
                22 { Write-Error "$errorMessage - Status Invalid Service Account" }
                23 { Write-Error "$errorMessage - Status Service Exists" }
                24 { Write-Error "$errorMessage - Service Already Paused" }
          }
       }
    }

    process {

        foreach($Computer in $ComputerName) {
            
            foreach($Credential in $ServiceCredential){ 

                foreach($Service in $ServiceName) {

                    Set-ServiceCredential $Service $Computer $Credential
                }
            }
        }
    }
}

Set-ServiceAccountPassword
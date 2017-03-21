<#
Current goals: 
- Integrate Get-NonStandardServiceAccounts script output (Not CSV output but, adjust for only $variable output).
- Pass/adjust needed variables along to Set-ServiceAccountPassword function. There are MANY that are not going to/coming from the right place.         
- Clear any variables containing secure information in cleartext after final conversion immediately after new passwords have been set.
- Complete all documentation
- May need to change KeePass location to network share when complete.

Achieved goals: 
- Access KeePass Master DB and retrieve all accounts information as a secure string.
- Bring secure string back to Binary, then to string again because change method doesn't accept Secure Strings.

Notes: This script is in beta testing at the current moment. Proper variables aren't set within several different functions; as I am 
testing individual functionality before integrating them with each other.

Feel free to add or adjust anything that you think could be helpful but, please review the current goals before implementing changes and submitting to me. 
#>

param(

$PathToKeePassFolder = "C:\Program Files (x86)\KeePass"
)
#Load all KeePass .NET binaries in the folder
(Get-ChildItem -Recurse $PathToKeePassFolder| Where {($_.Extension -EQ ".dll") -or ($_.Extension -eq ".exe")} | ForEach { $AssemblyName=$_.FullName; Try {[Reflection.Assembly]::LoadFile($AssemblyName) } Catch{ }} ) | Out-Null



function Find-PasswordInKeePassDBUsingPassword {

    [CmdletBinding()]
    [OutputType([String[]])]
    Param(

        #KeePass Database Path
        $PathToDB = "C:\Program Files (x86)\KeePass\EnterpriseServicesSchoolMaster.kdbx",

        #KeePass Database Master Password; secure-string            
        $MasterPasswordDB = (Read-Host -Prompt "KeePass Master Password" -AsSecureString )       
    )

    #Integrate output from Get-NonStandardServiceAccounts (NO CSV; output only)
    $FoundAccounts = #

    #Service Account Names
    $ServiceAccount = Split-Path -Path $FoundAccounts.StartName -Leaf
    
    #Pass Secure String to BinaryString
    $BSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($MasterPasswordDB)

    #Pass Binary String
    $Password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)

    #Empty array for later use in script
    $CurrentAccountData=@()

    Try {

        foreach($Account in $ServiceAccount) {

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

                    $tBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.Title));                   
                    $nBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.Name));    
                    $pBSTR = ([system.runtime.interopservices.marshal]::SecureStringToBSTR($SecureAccountData.PW));
                    
                    $tString = [system.runtime.interopservices.marshal]::PtrToStringAuto($tBSTR);      
                    $nString = [system.runtime.interopservices.marshal]::PtrToStringAuto($nBSTR); 
                    $pString = [system.runtime.interopservices.marshal]::PtrToStringAuto($pBSTR);  
                    
                    
                    $script:AccountData += [pscustomobject] @{
                        
                      Title =  $tString
                      Name =  $nString
                      PW =  $pString

                    }          
                }
            }

            #Close KeePass Database
            $PwDatabase.Close()
        }
    }

    Catch {

        Write-Host -ForegroundColor Yellow "An error ocurred. Please enter the correct Master Password."
        Break
    }

    #Zero out Binary String
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    #Remove secure variables from memory; remove/clear all created variables containing information
    Remove-Variable Password

    #Generate KeePass account output
    $Data
}

#Variable with working account information
$Data = Find-PasswordInKeePassDBUsingPassword 


function Set-ServiceAccountPassword {

    #Find a way to set credentials for multiple accounts, pass them to services based on account name.
    [CmdletBinding(SupportsShouldProcess=$true)]

    param(
      
        [Management.Automation.PSCredential[]] $ServiceCredential
    )

    function Set-ServiceCredential {

    param(
         
        #$Import needs to be information from Get-NonStandardServiceAccount 
        $Import = "#"
        $ServiceCredential=$Data
    )
    
        $Import = Import-CSV $CSVFile

        $ComputerName = $Import.SystemName
        $ServiceName = $Import.Name

        $wmiFilter = "Name='{0}' OR DisplayName='{0}'" -f $serviceName
        $params = @{

          "Class" = "Win32_Service"
          "ComputerName" = $computerName
          "Filter" = $wmiFilter
          "ErrorAction" = "Stop"
        }

        $WMIobj = Get-WmiObject @params


        if($PSCmdlet.ShouldProcess("Service '$serviceName' on '$computerName'","Set credentials")) {

          # See https://msdn.microsoft.com/en-us/library/aa384901.aspx
          $returnValue = ($WMIobj.Change($null,                  # DisplayName
            $null,                                               # PathName
            $null,                                               # ServiceType
            $null,                                               # ErrorControl
            $null,                                               # StartMode
            $null,                                               # DesktopInteract
            $serviceCredential.Name,                             # StartName
            $serviceCredential.PW,                               # StartPassword
            $null,                                               # LoadOrderGroup
            $null,                                               # LoadOrderGroupDependencies
            $null)).ReturnValue                                  # ServiceDependencies
          $errorMessage = "Error setting credentials for service '$serviceName' on '$computerName'"

            switch($returnValue) {

                0  { Write-Verbose "Set credentials for service '$serviceName' on '$computerName'" }
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

            foreach($Service in $ServiceName) {

                Set-ServiceCredential $Service $Computer $ServiceCredential 
            }
        }
    }
}

#Set-ServiceAccountPassword
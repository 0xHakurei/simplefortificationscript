#
#   Copyright© Hakurei Instruments
#   Version 0.0.1
#

<#
    function checkEnvironment(): Check current PowerShell version
    Return:[boolean]            Return true if Powershell Version is 5
#>
function checkEnvironment() {
    if($PSVersionTable.PSVersion.Major -eq 5) {
        return $true
    } else {
        return $false
    }
}

<#
    function updateEnvironment(): Update OS PowerShell version
    Return:0                    If all processes were executed correctly
#>
function updateEnvironment() {
    Write-Output "Updating system environment, attemping to install .net framework 4.5"
    .\dotnetfx45.exe /Q /NORESTART /lcid 1033
    while(Get-Process | Where-Object { $_.Name -eq "dotnetfx45" }){
        Start-Sleep(5)
    }
    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2008 R2*") {
        Dism.exe /online /add-package /packagepath:.\Windows6.1-KB3191566-x64.cab
    } elseif ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2012 R2*") {
        Dism.exe /online /add-package /packagepath:.\WindowsBlue-KB3191564-x64.cab
    } else {
        Write-Output "OS Type not supported by this script for now."
        return $false
    }
    return $true
}

<#
    function checkUserExistance([string]$userName): Check if a user already exists
    Param: String userName      Local UserName to be queried,
    Return: [boolean]           If target user exists then return TRUE, otherwise return FALSE
#>
function checkUserExistance([string]$userName) {
    $cu = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser"
    foreach($obj in $cu) {
        if(($obj.PartComponent -match $userName)) {
            return $true
        }
    }
    return $false
}

<#
    function fortify(): Fortify system security
    Return:0                    If all processes were executed correctly
#>
function fortify() {
    Write-Output "System Fortification Script"

    Write-Output "Creating Firewall Rules for Vulnerable Ports..."

    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2008 R2*") {
        #Disable TCP 445 SMB v1
        netsh.exe advfirewall firewall add rule name="Disable Port 445 Inbound" profile=any dir=in action=block remoteport=445 protocol=tcp enable=yes
        netsh.exe advfirewall firewall add rule name="Disable Port 445 Outbound" profile=any dir=out action=block remoteport=445 protocol=tcp enable=yes
        
        #Disable TCP 135 RPC
        netsh.exe advfirewall firewall add rule name="Disable Port 135 Inbound" profile=any dir=in action=block remoteport=135 protocol=tcp enable=yes
        netsh.exe advfirewall firewall add rule name="Disable Port 135 Outbound" profile=any dir=out action=block remoteport=135 protocol=tcp enable=yes
        
        #Disable TCP 139 NtwkShare
        netsh.exe advfirewall firewall add rule name="Disable Port 139 Inbound" profile=any dir=in action=block remoteport=139 protocol=tcp enable=yes
        netsh.exe advfirewall firewall add rule name="Disable Port 139 Outbound" profile=any dir=out action=block remoteport=139 protocol=tcp enable=yes
    } elseif ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2012 R2*") {
        #Disable TCP 445 SMB v1
        New-NetFirewallRule -DisplayName "Disable Port 445 Inbound" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
        New-NetFirewallRule -DisplayName "Disable Port 445 Outbound" -Direction Outbound -LocalPort 445 -Protocol TCP -Action Block

        #Disable TCP 135 RPC
        New-NetFirewallRule -DisplayName "Disable Port 135 Inbound" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Block
        New-NetFirewallRule -DisplayName "Disable Port 135 Outbound" -Direction Outbound -LocalPort 135 -Protocol TCP -Action Block

        #Disable TCP 139 NtwkShare
        New-NetFirewallRule -DisplayName "Disable Port 139 Network Share Inbound" -Direction InBound -LocalPort 139 -Protocol TCP -Action Block
        New-NetFirewallRule -DisplayName "Disable Port 139 Network Share Outbound" -Direction Outbound -LocalPort 139 -Protocol TCP -Action Block
    } else {
        Write-Output "OS Type not supported by this script for now."
        return $false
    }

    Write-Output "Disabling unnecessary services..."

    Stop-Service -Name Spooler -Force
    Stop-Service -Name Dhcp -Force
    Stop-Service -Name RemoteRegistry -Force

    Set-Service -Name Spooler -StartupType Disabled
    Set-Service -Name Dhcp -StartupType Disabled
    Set-Service -Name RemoteRegistry -StartupType Disabled 

    Write-Output "Importing Pre-defined Group Policy Settings..."

    Write-Output "Current OS Edition:" ((Get-WmiObject -Class Win32_OperatingSystem).Caption)

    #Import Group Policy Settings via SecEdit
    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2008 R2*") {
        SecEdit.exe /configure /db secedit.sdb /cfg .\model2008.inf
        Copy-Item -Path .\secedit.sdb -Destination C:\Windows\security\database -Force
        gpupdate.exe /force
    } elseif ((Get-WmiObject -Class Win32_OperatingSystem).Caption -like "*2012 R2*") {
        SecEdit.exe /configure /db secedit.sdb /cfg .\model2012.inf
        Copy-Item -Path .\secedit.sdb -Destination C:\Windows\security\database -Force
        gpupdate.exe /force
    } else {
        Write-Output "OS Type not supported by this script for now."
    }

    Write-Output "Creating Users..."

    #Define User Accounts
    $accountUser = "Lwzxjsb"
    $accountAudit = "Auditor"

    #Generate Formatted Random Password
    $pwdUser = "Lwzx!!" + (Get-Random -Maximum 9999 -Minimum 1000).ToString()
    $pwdAudit = "Aud1t@@" + (Get-Random -Maximum 9999 -Minimum 1000).ToString()

    if ((checkUserExistance $accountUser)) {
        Write-Output "Found pre-defined user: $accountUser , and its password is required to be changed."
        Set-LocalUser -Name $accountUser -Password (ConvertTo-SecureString -AsPlainText $pwdUser -Force) 
        if ((checkUserExistance $accountAudit)) {
            Write-Output "Found pre-defined user: $accountAudit , and its password is required to be changed."
            Set-LocalUser -Name $accountAudit -Password (ConvertTo-SecureString -AsPlainText $pwdAudit -Force)
        } else {
            New-LocalUser -Name $accountAudit -Password (ConvertTo-SecureString -AsPlainText $pwdAudit -Force) -FullName "Auditor"
            Add-LocalGroupMember -Group "Users" -Member $accountAudit
        }
    } else {
        if ((checkUserExistance $accountAudit)) {
            Write-Output "Found pre-defined user: $accountAudit , and its password is required to be changed."
            Set-LocalUser -Name $accountAudit -Password (ConvertTo-SecureString -AsPlainText $pwdAudit -Force)
        } else {
            New-LocalUser -Name $accountUser -Password (ConvertTo-SecureString -AsPlainText $pwdUser -Force) -FullName "Lwzxjsb"
            Add-LocalGroupMember -Group "Administrators" -Member $accountUser
            New-LocalUser -Name $accountAudit -Password (ConvertTo-SecureString -AsPlainText $pwdAudit -Force) -FullName "Auditor"
            Add-LocalGroupMember -Group "Users" -Member $accountAudit
        }
    }

    Write-Output "Users created, built-in Administrator account will now be disabled."

    Disable-LocalUser -Name "Administrator"

    $ipaddr = [System.Net.Dns]::GetHostAddresses((Get-WmiObject -Class Win32_ComputerSystem).name) |
    Where-Object {
        $_.AddressFamily -eq 'InterNetwork'
    } |
    Select-Object -ExpandProperty IPAddressToString

    $hostName = ((Get-WmiObject -Class Win32_ComputerSystem).name)

    Write-Output "Saving account information to .\AccountInfo-$hostName-$ipaddr.txt" 

    Write-Output "Account name: " $accountUser  "Password: " ($pwdUser.ToString()) `
    " "`
    "Account name: " $accountAudit  "Password: " ($pwdAudit.ToString()) `
    | Out-File AccountInfo-$hostName-$ipaddr.txt
    return ;
}

if(checkEnvironment) {
    fortify
} else {
    updateEnvironment
}
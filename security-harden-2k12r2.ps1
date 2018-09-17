$ErrorActionPreference = "silentlycontinue"

#region parameters
    param (
        [string] $timezone,
        [switch] $fwon,
        [switch] $IEESCon
        )
#endregion

#region House Keeping
    #Update Timezone
        if(!$timezone){
            C:\windows\system32\tzutil.exe /s "UTC"
        }
        else{
            C:\windows\system32\tzutil.exe /s $timezone
        }

    #Disable Windows Firewall 
        if($fwon.IsPresent){
            Set-NetFirewallProfile -Profile Public,Private -Enabled True
        }
        else{            
            Set-NetFirewallProfile -Profile Public,Private -Enabled False
        }

    #Disable IE Enhanced Security 
        if($IEESCon.IsPresent){
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
        }
        else{
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
        }
        
   #Start Windows Update Check
        $AutoUpdate = New-Object -ComObject "Microsoft.Update.AutoUpdate"
        $AutoUpdate.DetectNow()
#endregion 


#region SecurityHardening
#Empty Keys
        $key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                }

#SCHANNEL Logging 
        $key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "EventLogging" -Type "DWord" -Value "00000001"
                }

#Multi-Protocol Unified Hello 
        $key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client",
               "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "Enabled" -Type "DWord" -Value "00000000"
                    Set-ItemProperty -path "Registry::$k" -Name "DisabledByDefault" -Type "DWord" -Value "00000001"
                }

#PCT
        $key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client",
               "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "Enabled" -Type "DWord" -Value "00000000"
                    Set-ItemProperty -path "Registry::$k" -Name "DisabledByDefault" -Type "DWord" -Value "00000001"
                }

#SSL & TLS Keys
        $key =  "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "Enabled" -Type "DWord" -Value "00000000"
                    Set-ItemProperty -path "Registry::$k" -Name "DisabledByDefault" -Type "DWord" -Value "00000001"
                }

        $key =  "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "Enabled" -Type "DWord" -Value "ffffffff"
                    Set-ItemProperty -path "Registry::$k" -Name "DisabledByDefault" -Type "DWord" -Value "00000000"
                }

#Cipher Keys 

        $ciphers = "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"


        foreach($c in $ciphers){
            $key = "HKey_Local_Machine\" + $c
                If  ( -Not ( Test-Path "Registry::$key")){([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey($c)}
                        Set-ItemProperty -path "Registry::$key" -Name "Enabled" -Type "DWord" -Value "00000000"
                               }

#SMB Signing
        $key =  "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters",                
                "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "RequireSecuritySignature" -Type "DWord" -Value "1"
                }


        $key =  "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters",
                "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"                  

        foreach($k in $key){
                    If  ( -Not ( Test-Path "Registry::$k")){New-Item -Path "Registry::$k" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$k" -Name "EnableSecuritySignature" -Type "DWord" -Value "1"
                }
#endregion
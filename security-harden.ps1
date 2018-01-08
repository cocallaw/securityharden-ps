#region House Keeping
    #Update Timezone
        #Add logic for selectable TZ, must be FQ TZ name
            C:\windows\system32\tzutil.exe /s "Eastern Standard Time"

    #Disable Windows Firewall 
        Set-NetFirewallProfile -Profile Public,Private -Enabled False

    #Disable IE Enhanced Security 
        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

    #Disable UAC | Restart Required 
        $UACKey = "HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system"
        New-ItemProperty -Path $UACKey -Name "EnableLUA" -PropertyType DWord -Value "00000000" -Force

#endregion 


#region SecurityHardening

#SSL & TLS Keys
        $keys = "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
                "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"

        foreach($k in $keys){
                    $Key = $k
                    If  ( -Not ( Test-Path "Registry::$Key")){New-Item -Path "Registry::$Key" -ItemType RegistryKey -Force}
                    Set-ItemProperty -path "Registry::$Key" -Name "Enabled" -Type "DWord" -Value "00000000"
                }

#Cipher Keys 

        $ciphers = "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128",
                   "System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"


        foreach($c in $ciphers){
            $keys = "HKey_Local_Machine\" + $c
                If  ( -Not ( Test-Path "Registry::$Key")){([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey($c)}
                        Set-ItemProperty -path "Registry::$Key" -Name "Enabled" -Type "DWord" -Value "0"
                               }

#endregion
<#
.SYNOPSIS
    Emotet detection tool.

.DESCRIPTION
    This script is a PowerShell implementation of EmoCheck (https://github.com/JPCERTCC/EmoCheck)

.NOTES
    Version            : 1.0.5
    Author             : Egor Puzanov
    Created on         : 2020-02-09
    License            : MIT License
    Copyright          : (c) 2020 Egor Puzanov
    Purpose/Change     : Initial script development

.EXAMPLE
    PS> ./emockeck.ps1
    ComputerName       : localhost
    VolumeSerialNumber : 1900000
    EmotetProcessName  : purgeelem
    Status             : OK
    EmotetProcessID    :
    EmotetPath         :

.EXAMPLE
    PS> ./emockeck.ps1 -ComputerName "host1" -Credential "Administrator"
    ComputerName       : host1
    VolumeSerialNumber : 1900000
    EmotetProcessName  : purgeelem
    Status             : DETECTED
    EmotetProcessID    : 7002
    EmotetPath         : C:\Temp\purgeelem.exe

.EXAMPLE
    PS> @("host1", "host2") | ./emocheck.ps1 | Format-Table -Property ComputerName,Status
    ComputerName Status
    ------------ ------
    host1        DETECTED
    host2        OK

.EXAMPLE
    PS> Get-ADComputer -Filter 'Name -like "dc*"' | Select Name | ./emocheck.ps1 -CIMSessionOption $(New-CimSessionOption DCOM) | Select-Object -Property ComputerName,Status | Export-Csv -Path .\result.csv -NoTypeInformation
    PS> Get-Content -Path .\result.csv
    "ComputerName","Status"
    "dc001.domain.net","OK"
    "dc002.domain.net","OK"
    "dc003.domain.net","OK"

.LINK
    https://github.com/epuzanov/emocheckps

.INPUTS
    System.String. You can pipe ComputerName strings to emocheck.ps1

.OUTPUTS
    PSObject. emocheck.ps1 returns a PSObject with the Status of checks.

.PARAMETER ComputerName
    A list of Computer Names. The default is the localhost.

.PARAMETER Credential
    Specifies a user account that has permission to perform this action.
    The default is the current user.

.PARAMETER CIMSessionOption
    Specifies a CIM Session Option. If empty PSRemoting will be used. The default is empty.
#>

Param (
        [Parameter(
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)
        ]
        [System.String[]]
        $ComputerName = "localhost",
        [Parameter(Position=1)]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter(Position=2)]
        [Microsoft.Management.Infrastructure.Options.CimSessionOptions]
        $CIMSessionOption


)

Begin {
    $keywords = "duck,mfidl,targets,ptr,khmer,purge,metrics,acc,inet,msra,symbol,driver,sidebar,restore,msg,volume,cards,shext,query,roam,etw,mexico,basic,url,createa,blb,pal,cors,send,devices,radio,bid,format,thrd,taskmgr,timeout,vmd,ctl,bta,shlp,avi,exce,dbt,pfx,rtp,edge,mult,clr,wmistr,ellipse,vol,cyan,ses,guid,wce,wmp,dvb,elem,channel,space,digital,pdeft,violet,thunk"
    $status = New-Object PSObject
    $status | Add-Member NoteProperty ComputerName $null
    $status | Add-Member NoteProperty VolumeSerialNumber $null
    $status | Add-Member NoteProperty EmotetProcessName $null
    $status | Add-Member NoteProperty Status $null
    $status | Add-Member NoteProperty EmotetProcessID $null
    $status | Add-Member NoteProperty EmotetPath $null
}

Process {
    function Get-EmotetProcessWord {
        Param (
            [parameter(Position=0)]
            [System.UInt32]
            $seed
        )
        $ptr = $seed % $keywords.length
        $start = $keywords.Substring(0, $ptr + 1).LastIndexOf(",") + 1
        return $keywords.Substring($start, $keywords.IndexOf(",", $start) - $start)
    }

    function Get-EmotetProcessName {
        Param (
            [Parameter(Position=0)]
            [System.UInt32]
            $VolumeSerialNumber
        )
        $seed = [UInt32]::MaxValue - [UInt32]$($VolumeSerialNumber / $keywords.length)
        $keyword = $(Get-EmotetProcessWord $VolumeSerialNumber) + $(Get-EmotetProcessWord $seed) + ".exe"
        return $keyword
    }

    function Get-DecodeEmotetProcessName {
        Param (
            [Parameter(Position=0)]
            [System.Byte[]]
            $xor_key,
            [Parameter(Position=1)]
            [System.Byte[]]
            $reg_value
        )
        $filename = ""
        For ($i=0; $i -lt $reg_value.Length; $i++) {
            $decoded_char = $xor_key[$i % 4] -bxor $reg_value[$i]
            if (0x20 -Lt $decoded_char -And $decoded_char -Lt 0x7e) {
                $filename += [Char]$decoded_char
            }
        }
        if ($filename.Length -gt 0) {
            $filename += ".exe"
        }
        return $filename
    }
    
    $ValuesRequest_SB = {
        Param (
            [Parameter(Position=0)]
            [Microsoft.Management.Infrastructure.CimSession]
            $CimSession
        )
        $reg_keys = $("0x80000001:Software\Microsoft\Windows\CurrentVersion\Explorer",
            "0x80000002:Software\Microsoft\Windows\CurrentVersion\Explorer", 
            "0x80000002:WOW6432Node\Software\Microsoft\Windows\CurrentVersion\Explorer")
        $results = @()
        $SystemDrive = Get-CimInstance -CimSession $CimSession -Namespace 'root/cimv2' -ClassName Win32_OperatingSystem -Property SystemDrive | Select-Object -ExpandProperty SystemDrive
        $SystemDrive += "\\"
        $results += Get-CimInstance -CimSession $CimSession -Namespace 'root/cimv2' -ClassName Win32_Volume -Filter "Name='$SystemDrive'" -Property SerialNumber | Select-Object -ExpandProperty SerialNumber
        $results += '{0:X}' -f $results[0]
        $arguments = @{sValueName=$results[1]}
        ForEach ($reg_key in $reg_keys) {
            [System.UInt32]$arguments.hDefKey,[System.String]$arguments.sSubKeyName = $reg_key.Split(":")
            $bs = Invoke-CimMethod -CimSession $CimSession -Namespace 'root/cimv2' -ClassName 'StdRegProv' -MethodName 'GetBinaryValue' -Arguments $arguments | Select-Object -ExpandProperty uValue
            if ($bs -ne $null) {
                $results += [System.BitConverter]::ToString($bs).Replace("-", "")
            }
        }
        $results
    }

    $ProcessStatus_SB = {
        Param (
            [Parameter(Position=0)]
            [Microsoft.Management.Infrastructure.CimSession]
            $CimSession,
            [Parameter(Position=1)]
            [System.String]
            $filter
        )
        Get-CimInstance -CimSession $CimSession -Namespace 'root/cimv2' -ClassName Win32_Process -Filter $filter -Property Name,Handle,ExecutablePath
    }

    ForEach($HostName in $ComputerName) {
        $status.ComputerName = $HostName
        $status.EmotetProcessID = $null
        $status.EmotetPath = $null
        $status.Status = "OK"
        $parameters = @{}
        $CimSession = New-CimSession
        $process_names = [System.Collections.ArrayList]@()
        try {
            if ($status.ComputerName -ne "localhost") {
                if ($CIMSessionOption -eq $null) {
                    $parameters.ComputerName = $status.ComputerName
                    if ($Credential) {
                        $parameters.Credential = $Credential
                    }
                } else {
                    $CimSession = New-CimSession -ErrorAction Stop -ComputerName $status.ComputerName -Credential $Credential -SessionOption $CIMSessionOption
                }
            }
            $cim_results = [System.Collections.ArrayList]$(Invoke-Command -ErrorAction Stop -ArgumentList $CimSession -ScriptBlock $ValuesRequest_SB @parameters)
            $status.VolumeSerialNumber = $cim_results[0]
            $status.EmotetProcessName = $(Get-EmotetProcessName $status.VolumeSerialNumber)
            $filter = "Name='" + $status.EmotetProcessName + "'"
            $xor_key = [Byte[]] -split ($cim_results[1] -replace '..', '0x$& ')
            $xor_key = @($xor_key[3], $xor_key[2], $xor_key[1], $xor_key[0])
            $cim_results.RemoveAt(0)
            $cim_results.RemoveAt(0)
            ForEach ($reg_value in $cim_results) {
                $filter += " OR Name='" + $(Get-DecodeEmotetProcessName $xor_key $([Byte[]] -split ($reg_value -replace '..', '0x$& '))) + "'"
            }
            $processes = Invoke-Command -ErrorAction Stop -ArgumentList $CimSession,$filter -ScriptBlock $ProcessStatus_SB @parameters
            ForEach($process in $processes) {
                $status.EmotetProcessName = $process.Name
                $status.EmotetProcessID = $process.Handle
                $status.EmotetPath = $process.ExecutablePath
                $status.Status = "DETECTED"
                break
            }
        } catch {
            if (Test-Connection $status.ComputerName -count 1 -Quiet) {
                $status.Status = "UNKNOWN"
            } else {
                $status.Status = "OFFLINE"
            }
        }
        $status
    }
}

End {
}

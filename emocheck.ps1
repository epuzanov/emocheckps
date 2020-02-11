<#
.SYNOPSIS
    Emotet detection tool.

.DESCRIPTION
    This script is a PowerShell implementation of EmoCheck (https://github.com/JPCERTCC/EmoCheck)

.NOTES
    Version            : 1.0.2
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
    PS> Get-ADComputer -Filter 'Name -like "dc*"' | Select Name | ./emocheck.ps1 | Select-Object -Property ComputerName,Status | Export-Csv -Path .\result.csv -NoTypeInformation
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
#>

Param (
        [Parameter(Position=0)]
        [PSCredential]
        $Credential,
        [Parameter(
            Position=1,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)
        ]
        [String[]]
        $ComputerName="localhost"
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
            [UInt32]
            $seed
        )
        $ptr = $seed % $keywords.length
        $start = $keywords.Substring(0, $ptr + 1).LastIndexOf(",") + 1
        return $keywords.Substring($start, $keywords.IndexOf(",", $start) - $start)
    }

    function Get-EmotetProcessName {
        Param (
            [Parameter(Position=0)]
            [UInt32]
            $VolumeSerialNumber
        )
        $seed = [UInt32]::MaxValue - [UInt32]$($VolumeSerialNumber / $keywords.length)
        $keyword = $(Get-EmotetProcessWord $VolumeSerialNumber) + $(Get-EmotetProcessWord $seed)
        return $keyword
    }

    foreach($HostName in $ComputerName) {
        $status.ComputerName = $HostName
        $status.EmotetProcessID = $null
        $status.EmotetPath = $null
        $parameters = @{}
        if ($status.ComputerName -ne "localhost") {
            $parameters.ComputerName = $status.ComputerName
            if ($Credential) {
                $parameters.Credential = $Credential
            }
        }
        try {
            $status.VolumeSerialNumber = (Invoke-Command @parameters { Get-CimInstance -ClassName Win32_Volume -Filter "name='C:\\'" }).SerialNumber
            $status.EmotetProcessName = $(Get-EmotetProcessName $status.VolumeSerialNumber)
            $process = (Invoke-Command @parameters { Get-CimInstance -ClassName Win32_Process -Filter "Name like '$($status.EmotetProcessName)%'" })
            if ($process) {
                $status.EmotetProcessID = $process.Handle
                $status.EmotetPath = $process.ExecutablePath
                $status.Status = "DETECTED"
            } else {
                $status.Status = "OK"
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

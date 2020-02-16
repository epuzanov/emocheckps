# emocheck.ps1
This script is a PowerShell implementation of EmoCheck (https://github.com/JPCERTCC/EmoCheck) from JPCERT Coordination Center.

## Why?
1. This script supports remote checks over WMI, WS-Management or WinRM transport.
2. This script supports PIPE Input/Output.

## How to use?
1. Download emocheck.ps1
2. Run PowerShell console
3. Run emocheck.ps1 on the host

## Examples
Local check

```
PS>./emockeck.ps1
```

Remote check over WinRM

```
PS>./emockeck.ps1 -ComputerName "host1" -Credential "Administrator"
```

Remote check over WS-Management

```
PS>@("host1", "host2") |  -Credential "Administrator" -CIMSessionOption $(New-CimSessionOption -Protocol Wsman)
```

Remote check over WMI and store result in CSV File

```
 PS>Get-ADComputer -Filter 'Name -like "dc*"' | Select Name | ./emocheck.ps1 -CIMSessionOption $(New-CimSessionOption DCOM) | Select-Object -Property ComputerName,Status | Export-Csv -Path .\result.csv -NoTypeInformation
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments
JPCERT Coordination Center for original EmoCheck Software

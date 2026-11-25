$filter = @{ LogName = 'Security'; Id = 4624, 4625, 4740; StartTime = (Get-Date).AddDays(-1) }

Get-WinEvent -FilterHashtable $filter | ForEach-Object {
    $data = @{}
    foreach ($d in ([xml]$_.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
        Time      = $_.TimeCreated.ToString('s')
        EventID   = $_.Id
        User      = $data['TargetUserName']
        IP        = $data['IpAddress']
        LogonType = $data['LogonType']
    }
} | Export-Csv -Path "$PSScriptRoot\events.csv" -NoTypeInformation -Encoding UTF8

Write-Host "events.csv ban gayi"
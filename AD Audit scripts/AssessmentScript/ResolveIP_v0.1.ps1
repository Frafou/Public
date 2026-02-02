$ips = Import-Csv -Path ".\IPlist.txt"
$outfile = "Hostnamelist.txt"
$array= @()

foreach ($ip in $ips)
   { 
   Write-host "Try to resove IP:" $ip.ip
   try {$hostname =[System.Net.Dns]::GetHostByAddress($ip.ip).Hostname
        Write-host "Resolved IP: " $ip.ip "HostName:" $hostname -ForegroundColor green
       }
   catch { $hostname =""
           Write-host "Failed to resove IP: " $ip.ip -ForegroundColor Red
         }
     
   $Object = New-Object PSObject
   $Object | Add-Member -MemberType NoteProperty -Name "IP" -Value $ip.ip
   $Object | Add-Member -MemberType NoteProperty -Name "HostName" -Value $hostname
   
   $array += $Object
   }

   
# Now exporting the array to a CSV file
$path = Get-Location
Write-host "Outfile " $path"\"$OutFile -ForegroundColor green
$array | Export-Csv -Path .\$outfile -NoTypeInformation -Delimiter ";"
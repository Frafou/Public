Import-Module activedirectory

$domain = Get-ADDomain -Current LocalComputer

$OutFile = $domain.name + '-ListZoneDns.csv'
$DCs = Get-ADDomainController -Filter *
$outZone = @()

if ($DCs) {
   foreach ($DC in $DCs) {
      #Get DNS Zone
      #$DNS= Get-DnsServerZone -ComputerName $dc.name | select DNSServerName, * | foreach {$_.DNSServerName = $DC.Name;$_} | Export-Csv .\$OutFile -NoTypeInformation -Delimiter ";"
      #$DNS= invoke-command -ComputerName $dc.name {dnscmd /enumzones} #| select DNSServerName, * | foreach {$_.DNSServerName = $DC.Name;$_} | Export-Csv .\$OutFile -NoTypeInformation -Delimiter ";"
      $enumZonesExpression = 'dnscmd ' + $dc.name + ' /enumzones'
      $dnscmdOut = Invoke-Expression $enumZonesExpression
      if (-not($dnscmdOut[$dnscmdOut.Count - 2] -match 'Command completed successfully.')) {
         Write-Host $dc.name 'Failed to enumerate zones' -ForegroundColor red
         $zoneInfo = @{
            Computer   = $dc.name;
            Name       = '';
            ZoneType   = '';
            Storage    = '';
            Properties = ''
         }
         $zoneObject = New-Object PSObject -Property $zoneInfo
         $zones += $zoneObject

         $outZone += $zones


      } else {
         Write-Host $dc.name 'readed DNS zones' -ForegroundColor green
         # The output header can be found on the fifth line:
         $zoneHeader = $dnscmdOut[4]

         # Let's define the the index, or starting point, of each attribute:
         $d1 = $zoneHeader.IndexOf('Zone name')
         $d2 = $zoneHeader.IndexOf('Type')
         $d3 = $zoneHeader.IndexOf('Storage')
         $d4 = $zoneHeader.IndexOf('Properties')

         # Finally, let's put all the rows in a new array:
         $zoneList = $dnscmdOut[6..($dnscmdOut.Count - 5)]

         # This will store the zone objects when we are done:
         $zones = @()

         # Let's go through all the rows and extrapolate the information we need:
         foreach ($zoneString in $zoneList) {
            $zoneInfo = @{
               Computer   = $dc.name;
               Name       = $zoneString.SubString($d1, $d2 - $d1).Trim();
               ZoneType   = $zoneString.SubString($d2, $d3 - $d2).Trim();
               Storage    = $zoneString.SubString($d3, $d4 - $d3).Trim();
               Properties = @($zoneString.SubString($d4).Trim() -split ' ')
            }
            $zoneObject = New-Object PSObject -Property $zoneInfo
            $zones += $zoneObject
         }

         $outZone += $zones

      }


   }
   $path = Get-Location
   Write-Host 'Outfile ' $path"\"$OutFile -ForegroundColor green
   $outZone | Export-Csv -Path .\$OutFile -NoTypeInformation -Delimiter ';'

}





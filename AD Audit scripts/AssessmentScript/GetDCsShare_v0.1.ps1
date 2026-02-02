
Import-Module activedirectory

$domain = Get-ADDomain -Current LocalComputer
$path = Get-Location

$OutFile = $path.Path + "\" + $domain.name + "-DCsShare.csv"
Write-host "Outfile " $OutFile -ForegroundColor green

"Computer;Sharename;Path;Description" | out-file -FilePath $OutFile 


$computers= Get-ADDomainController -filter * 


foreach ($computer in $computers)
{
    Write-host "Querying information about the computer: " $computer.name  -ForegroundColor green 

    #Querying information about the computer
    $query = Get-WmiObject -Class Win32_Share -ComputerName $computer.name
    
    foreach ($share in $query)
      {
        $computer.name + ";" + $share.Name + ";" + $share.Path + ";" + $share.Description  | out-file -FilePath $OutFile -Append
    
      }
    
}

Write-host "Outfile " $OutFile -ForegroundColor green
Write-host "Done " -ForegroundColor green



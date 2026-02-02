
Import-Module activedirectory

$domain = Get-ADDomain -Current LocalComputer

$OutFile = $domain.name + "-DCsHW.csv"

$computers= Get-ADDomainController -filter *

# Creating an empty array, will be used later
$array= @()

foreach ($computer in $computers)
{
    Write-host "Querying information about the computer: " $computer.name  -ForegroundColor green 

    #Querying information about the computer
    $query = Get-WmiObject -Class win32_computersystem -ComputerName $computer.name
    $name = $query.Name
    if (!$name) {$name = $computer.name} 
    $make = $query.Manufacturer
    $model = $query.Model
    $ram = $query.TotalPhysicalMemory/1Gb
    $os = (Get-WmiObject -Class win32_operatingsystem -ComputerName $computer.name).Caption
    $temp = Get-WmiObject -Class Win32_processor -ComputerName $computer.name
    $cpu = $temp.Name
    $NumberOfCores = $temp.NumberOfCores
    $NumberOfLogicalProcessors = $temp.NumberOfLogicalProcessors
    
    #$users = $query.Username

    # Now creating an populating the array. Change the collumns name if you wish
    $Object = New-Object PSObject
    $Object | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $name
    $Object | Add-Member -MemberType NoteProperty -Name "Make" -Value $make
    $Object | Add-Member -MemberType NoteProperty -Name "Model" -Value $model
    $Object | Add-Member -MemberType NoteProperty -Name "RAM" -Value $ram
    $Object | Add-Member -MemberType NoteProperty -Name "OS" -Value $os
    $Object | Add-Member -MemberType NoteProperty -Name "CPU" -Value $cpu
    $Object | Add-Member -MemberType NoteProperty -Name "NumberOfCores" -Value $NumberOfCores
    $Object | Add-Member -MemberType NoteProperty -Name "NumberOfLogicalProcessors" -Value $NumberOfLogicalProcessors
    #$Object | Add-Member -MemberType NoteProperty -Name "LoggedOnUsers" -Value $users
    $array += $Object
}

# Now exporting the array to a CSV file
$path = Get-Location
Write-host "Outfile " $path"\"$OutFile -ForegroundColor green
$array | Export-Csv -Path .\$OutFile -NoTypeInformation -Delimiter ";"
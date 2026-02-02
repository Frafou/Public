' USAGE: cscript .\GetDCConfiguration.vbs <domain DN>
' The first parameter must be in the DN format "DC=example,DC=com"
Dim args, strDomain
Set args = WScript.Arguments

If args.count <> 1 Then
	WScript.Echo "USAGE: cscript .\GetDCConfiguration.vbs <domain DN>"
	WScript.Quit
End If

strDomain = args.Item(0)
WScript.Echo "Argument: " & strDomain 
WScript.Echo


sFilePathDNS = strDomain & "DNSOldConfiguration.csv"
sFilePathSW = strDomain & "SoftwareInstalled.csv"
sFilePathSF = strDomain & "ServerFeature.csv"


Dim objFSODNS,objFSOSW,objFSOSF
Dim objTextFileDNS,objTextFileSW,objTextFileSF

WScript.Echo "Try to create file: " & sFilePathDNS
Set objFSODNS = CreateObject("Scripting.FileSystemObject")
Set objTextFileDNS = objFSODNS.CreateTextFile(sFilePathDNS, True)
objTextFileDNS.WriteLine "Computer" & ";" & "MACAddress" & ";" & _
    "DNSConfiguration"
WScript.Echo "File created: " & sFilePathDNS
WScript.Echo

WScript.Echo "Try to create file: " & sFilePathSW
Set objFSOSW = CreateObject("Scripting.FileSystemObject")
Set objTextFileSW = objFSOSW.CreateTextFile(sFilePathSW, True)
objTextFileSW.WriteLine "Computer" & ";" & "Caption" & ";" & _
    "Description" & ";" & "Identifying Number" & ";" & _
    "Install Date" & ";" & "Install Location" & ";" & _
    "Install State" & ";" & "Name" & ";" & _
    "Package Cache" & ";" & "SKU Number" & ";" & "Vendor" & ";" _
     & "Version"
WScript.Echo "File created: " & sFilePathSW
WScript.Echo

WScript.Echo "Try to create file: " & sFilePathSF
Set objFSOSF = CreateObject("Scripting.FileSystemObject")
Set objTextFileSF = objFSODNS.CreateTextFile(sFilePathSF, True)
objTextFileSF.WriteLine "Computer" & ";" & "ServerFeature"
WScript.Echo "File created: " & sFilePathSF
WScript.Echo

EnumDCs

WScript.Echo "Close Files"

objTextFileDNS.Close
objTextFileSW.Close
objTextFileSF.Close
WScript.Echo "Done"


Sub EnumDCs
        on error resume next
        WScript.Echo "Try to read Domain Controller"
	    Set objOU = GetObject("LDAP://ou=Domain Controllers," & strDomain) 
	    objOU.Filter = Array("Computer")
	       
	
	    For Each objComputer in objOU
            WScript.Echo "Read from: " & objComputer.CN
            QueryDNS objComputer.CN
            EnumSoftware objComputer.CN
            ServerFeature objComputer.CN
        Next

        WScript.Echo "Try to read Nexted OU"
	    Set objOUnext = GetObject("LDAP://ou=Domain Controllers, " & strDomain) 
	    objOUnext.Filter = Array("organizationalUnit")
	       
	
	    For Each OU in objOUnext
            WScript.Echo "Try to read Domain Controller from OU: " & OU.distinguishedName
            Set objOU = GetObject("LDAP://" & OU.distinguishedName) 
	        objOU.Filter = Array("Computer")
	     
	        For Each objComputer in objOU
                WScript.Echo "Read from: " & objComputer.CN
                QueryDNS objComputer.CN
                EnumSoftware objComputer.CN
                ServerFeature objComputer.CN
            Next
          
        Next
        
    
End Sub


SUB QueryDNS(strServerName)
    on error resume next
    Set objWMIService =    GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strServerName & "\root\cimv2")
    Set colNICConfigs = objWMIService.ExecQuery("SELECT    DNSServerSearchOrder, Description, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")
    for each objNICConfig in colNICConfigs
        OldDNSConfiguration = Join(objNICConfig.DNSServerSearchOrder, ",")
        objTextFileDNS.WriteLine(strServerName & ";" & objNICConfig.MACAddress &";"& OldDNSConfiguration)
    next
END SUB


SUB EnumSoftware (strServerName) 
    on error resume next
    Set objWMIService = GetObject("winmgmts:" _
      & "{impersonationLevel=impersonate}!\\" & strServerName & "\root\cimv2")
    Set colSoftware = objWMIService.ExecQuery _
      ("SELECT * FROM Win32_Product")
    For Each objSoftware in colSoftware

        objTextFileSW.WriteLine strServerName & ";" & objSoftware.Caption & ";" & _
        objSoftware.Description & ";" & _
        objSoftware.IdentifyingNumber & ";" & _
        objSoftware.InstallLocation & ";" & _
        objSoftware.InstallState & ";" & _
        objSoftware.Name & ";" & _
        objSoftware.PackageCache & ";" & _
        objSoftware.SKUNumber & ";" & _
        objSoftware.Vendor & ";" & _
        objSoftware.Version
    Next

End SUB


SUB ServerFeature(strServerName)


Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strServerName & "\root\cimv2")
Set colRoleFeatures = objWMIService.ExecQuery ("Select * from Win32_ServerFeature")
For Each objRoleFeatures in colRoleFeatures
    objTextFileSF.WriteLine strServerName & ";" & objRoleFeatures.Name

Next

End SUB
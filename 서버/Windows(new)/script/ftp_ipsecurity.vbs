Dim Result
Dim IISObj
Dim objFSO, objTextFile

Set IISObj = GetObject("IIS://localhost/MSFTPSVC")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objTextFile = objFSO.CreateTextFile("ftp-ipsecurity.txt", True)

for each IISSite in IISObj
if (IISSite.Class = "IIsFtpServer") Then

IIsObjectPath = "IIS://localhost/MSFTPSVC/" & IISSite.Name & "/ROOT"
Set IIsObject = GetObject(IIsObjectPath)

Set objIpSecurity = IIsObject.Get("IPSecurity")
If objIpSecurity.GrantByDefault = TRUE Then
objTextFile.WriteLine("* SiteName: " & IISSite.ServerComment & " -> IP Security 설정 : Access Allow")
Else
objTextFile.WriteLine("* SiteName: " & IISSite.ServerComment & " -> IP Security 설정 : Access Deny")
End If

End If

Next
set WshShell = WScript.CreateObject("WScript.Shell")
Const ForReading = 1
Const ForWriting = 2
Const ForAppending = 8
Set Shell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
 
  WshShell.Run "cmd"
  WScript.Sleep 100
  WshShell.AppActivate "C:\Windows\system32\cmd.exe"
 
  WScript.Sleep 100
  rem telnet [address] [port]
  WshShell.SendKeys "telnet -f smtp_banner.txt " + "localhost" + " 25{ENTER}"
 
  WScript.Sleep 1500
  WshShell.SendKeys "quit" + "{ENTER}"

  WScript.Sleep 1000
  WshShell.SendKeys "{ENTER}"
  WshShell.SendKeys "{ENTER}"

  WScript.Sleep 1500
  WshShell.SendKeys "exit{ENTER}"

 
WScript.Sleep 1500


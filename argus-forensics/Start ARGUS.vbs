' ARGUS Forensics — double-click launcher (no console window).
' Starts the workbench minimized and opens your browser.

Option Explicit

Dim shell, fso, appDir, batPath, rc

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
appDir = fso.GetParentFolderName(WScript.ScriptFullName)
batPath = fso.BuildPath(appDir, "ARGUS.bat")

If Not fso.FileExists(batPath) Then
    MsgBox "ARGUS.bat was not found next to this launcher." & vbCrLf & vbCrLf & _
           "Expected:" & vbCrLf & batPath, vbCritical, "ARGUS Forensics"
    WScript.Quit 1
End If

shell.CurrentDirectory = appDir
rc = shell.Run("""" & batPath & """", 7, False)

If rc <> 0 Then
    MsgBox "ARGUS could not start (exit code " & rc & ")." & vbCrLf & vbCrLf & _
           "Double-click ARGUS.bat instead to see the full error message.", _
           vbExclamation, "ARGUS Forensics"
End If

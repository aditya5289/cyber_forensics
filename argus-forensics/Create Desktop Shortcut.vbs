Set oWS = WScript.CreateObject("WScript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")
sLinkFile = oWS.SpecialFolders("Desktop") & "\ARGUS Forensics.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = oFSO.GetParentFolderName(WScript.ScriptFullName) & "\Start ARGUS.vbs"
oLink.WorkingDirectory = oFSO.GetParentFolderName(WScript.ScriptFullName)
oLink.Description = "ARGUS Forensics workbench"
oLink.IconLocation = "%SystemRoot%\System32\imageres.dll,109"
oLink.Save

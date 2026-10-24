' make_iso.vbs -- create a Joliet ISO with IMAPI2
' usage: cscript //nologo make_iso.vbs <payload-dir> <output.iso>
Option Explicit
Dim fsi, result, stream, src, dst
If WScript.Arguments.Count < 2 Then
    WScript.Echo "usage: make_iso.vbs <payload-dir> <output.iso>"
    WScript.Quit 2
End If
src = WScript.Arguments(0)
dst = WScript.Arguments(1)

Set fsi = CreateObject("IMAPI2FS.MsftFileSystemImage")
fsi.FileSystemsToCreate = 3
fsi.VolumeName = "OPANDA_TEST"
fsi.Root.AddTree src, False
Set result = fsi.CreateResultImage()
Set stream = result.ImageStream
stream.SaveToFile dst, 0
WScript.Echo "ISO: " & dst

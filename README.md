# MOTW-Bypass: exe in lnk
Older Mark Of The Web Bypass that combines several techniques - we like 'em all

```powershell
$  python3 .\MOTW_Bypass_exe_in_lnk.py .\testcmd.exe testlink.lnk
```

Script packs an exe file into an `lnk` - this still works on latest patch level, as far as we could tell. 

We got it this far yet:
- Packed encrypted `.exe` in link file
- Correct offsets, packed payload as link target
- Code execution (powershell) on double-click
- Correct icon (notepad)
- Spoofed hover description
- Theoretically there could be a way to hide the command, using spaces. Not yet working

We're not so much interested with the packed `exe` and the actual MOTW Bypass, albeit it's nice-to-have. The `stageless` MOTW is probably a bit pointless - if it works at all, or not - cause regular Browsers like Chrome will go on **red alert** when downloading such a prepared file, making the user jump hoops to keep the download at all. 

What's much better is the entire combo of things. Powershell execution is all we need - in a nice package. 

However we're not yet finished with the `unpacking` and that part of the powershell payload. This last part will also make the rest of the powershell code fail currently. If you remove everything after `echo 1 > t` and double click the created file, it will work and write to the testfile `t`. 

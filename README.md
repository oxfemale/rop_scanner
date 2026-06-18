# rop_scanner
Gadget scanner that finds ROP gadgets inside any Windows DLL
```
rop_scanner.exe ntdll.dll --type rop
rop_scanner.exe ntdll.dll --type jop
rop_scanner.exe ntdll.dll --type syscall
rop_scanner.exe ntdll.dll --only "pop rcx,pop rdx,pop r8,pop r9"
rop_scanner.exe ntdll.dll --badbytes 00,0a,0d
rop_scanner.exe ntdll.dll --min-score 80
```

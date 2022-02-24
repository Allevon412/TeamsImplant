# TeamsImplant

This project is a stealthy teams implant that proxies the urlmon.dll that teams uses compile and throw this bad boy in the teams directory as urlmon.dll and you got yourself a persistence backdoor whenever teams runs by a user or at startup.

Features:
- Mutex so you don't get spammed with 10 shells when teams creates 10 different teams processes and loads the proxy DLL into each of them.
- Performs Unhooking of DLLs so we can call normal shellcode injection functions without worry.
- uses AES encyrption of the shellcode so we can embed the shellcode in our implant without it being detected. 
- used metasploit to generate shellcode with exitfunc=thread so we dont kill teams process when we exit our meterpreter session.

For an example of how it works review the below video:


https://user-images.githubusercontent.com/41178870/155579560-088ee7dc-d1e9-41e2-a760-1520b478bd9e.mp4


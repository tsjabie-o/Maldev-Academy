#include <stdio.h>
#include <Windows.h>
#include <psapi.h>
#include "headers.h"
#include <stdint.h>

const wchar_t cProcessName[] = L"Notepad.exe";

int Nt() {
    fnNtQuerySystemInformation pNtQSI = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQuerySystemInformation");
    if (pNtQSI == NULL) {
        printf("Could not load ntdll function, error:%d\n", GetLastError());
        return -1;
    }

    NTSTATUS status;
    size_t sSPI = 500000;
    PSYSTEM_PROCESS_INFORMATION pSPI = (PSYSTEM_PROCESS_INFORMATION)malloc(sSPI);
    DWORD returnedLength;

    if ((status = pNtQSI(SystemProcessInformation, pSPI, sSPI, &returnedLength)) != 0x0) {
        printf("Could not get process information array, ntstatus 0x%0.8X\n", status);
        if (returnedLength >= sSPI) {
            printf("Returned length is %d\n", returnedLength);
        }
        free(pSPI);
        return -1;
    }

    PVOID pToFree = pSPI;
    HANDLE hProcess;
    DWORD dwProcessID;

    while (TRUE)
    {
        if (pSPI->ImageName.Length && wcscmp(pSPI->ImageName.Buffer, cProcessName) == 0)
        {
            dwProcessID = (DWORD)(uintptr_t) pSPI->UniqueProcessId;
            printf("Found process with PID %d\n", dwProcessID);
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
            break;
        }
        if (pSPI->NextEntryOffset == 0) {
            break;
        }
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSPI + pSPI->NextEntryOffset);
    }

    free(pToFree);

    if (hProcess == NULL) {
        printf("Could not open process with pid %d, error: %d\n", dwProcessID, GetLastError());
        return -1;
    }

    return 0;
}

int WinApi() {
    DWORD dwPIDs[1024];
    DWORD dwBytesReturned;
    int amountProcess;

    if (!EnumProcesses(dwPIDs, sizeof(dwPIDs), &dwBytesReturned)) {
        printf("Could not enumerate processes. Error: %d\n", GetLastError());
        return -1;
    }

    amountProcess = dwBytesReturned / sizeof(DWORD);

    if (dwBytesReturned == sizeof(dwPIDs)) {
        printf("Sanity check failed - size of PID array is %d bytes, amount of bytes returned is %d\n", sizeof(dwPIDs), dwBytesReturned);
    }
    printf("Found %d processes\n", amountProcess);

    HANDLE hProcess;
    HMODULE hModule;
    DWORD dwBytesNeeded;
    wchar_t wcModuleName[100];

    for (size_t i = 1; i < amountProcess; i++) {
        if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPIDs[i])) == NULL) {
            continue;
        }
        if(!EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwBytesNeeded)) {
            printf("Could not enumerate process modules of process %d. Error: %d\n", dwPIDs[i], GetLastError());
            CloseHandle(hProcess);
            continue;
        }

        if (GetModuleBaseNameW(hProcess, hModule, wcModuleName, 100) == 0) {
            printf("Could not get module base name, error: %d\n", GetLastError());
            CloseHandle(hProcess);
            continue;
        }

        if (!wcscmp(cProcessName, wcModuleName)) {
            printf("Found process %d", dwPIDs[i]);
            CloseHandle(hProcess);
            return 0;
        }
        // Not the process we look for
        CloseHandle(hProcess);
    }

    // Process does not exist
    printf("Could not find process");
    return -1;
}

int main() {
    return Nt();
}
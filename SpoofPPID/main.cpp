#include <windows.h>
#include <psapi.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    DWORD dwPIDs[1024];
    DWORD dwBytesNeeded;

    if (!EnumProcesses(dwPIDs, sizeof(dwPIDs), &dwBytesNeeded)) {
        printf("Could not enumerate processes. Error %d\n", GetLastError());
        return -1;
    }

    HANDLE hParentProcess;
    HMODULE hModule;
    DWORD dwBytesNeeded2;
    char wcModuleName[MAX_PATH];

    for (size_t i = 0; i < dwBytesNeeded / sizeof(DWORD); i++)
    {
        if (dwPIDs[i] == 0) {
            continue;
        }

        hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPIDs[i]);
        if (!EnumProcessModules(hParentProcess, &hModule, sizeof(HMODULE), &dwBytesNeeded2)) {
            // printf("Could not enumerate modules of process %d. Error %d\n", dwPIDs[i], GetLastError());
            continue;
        }

        if (!GetModuleBaseNameA(hParentProcess, hModule, wcModuleName, MAX_PATH)) {
            printf("Could not get module base name of process %d. Error %d\n", dwPIDs[i], GetLastError());
            continue;
        }

        if (strcmp(wcModuleName, argv[1]) == 0) {
            printf("Found process %s with pid %d\n", wcModuleName, dwPIDs[i]);
            break;
        } else {
            hParentProcess = NULL;
        }
    }

    if (hParentProcess == NULL) {
        printf("Could not find the target process. Exiting..\n");
        return -1;
    }

    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    RtlSecureZeroMemory(&si, sizeof(STARTUPINFOEXW));
    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    SIZE_T szAttributeListSize;
    InitializeProcThreadAttributeList(NULL, 1, 0, &szAttributeListSize);
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) malloc(szAttributeListSize);
    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &szAttributeListSize)) {
        printf("Could not initialize tread attribute list. Error %d\n", GetLastError());
        return -1;
    }

    if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        printf("Could not update thread attribute list. Error %d\n", GetLastError());
        return -1;
    }

    si.lpAttributeList = pAttributeList;

    if (!CreateProcessW(L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2402.22.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe", NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, L"C:\\Windows\\", &(si.StartupInfo), &pi)) {
        printf("Could not create process. Error %d\n", GetLastError());
        return -1;
    }

    DeleteProcThreadAttributeList(pAttributeList);
    CloseHandle(hParentProcess);

    DWORD dwPID = pi.dwProcessId;
    printf("Created process with PID %d\nPress enter to quit.", dwPID);
    getchar();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
}
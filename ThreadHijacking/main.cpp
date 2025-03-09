#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void SafeFunction() {
    printf("Executing safe function\n");
    return;
}

void UnsafeFunction() {
    printf("Executing some malicious code!\n");\
    return;
}

int main() {
    DWORD dwTID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) &SafeFunction, NULL, CREATE_SUSPENDED, &dwTID);

    CONTEXT cThreadContext = {
        .ContextFlags = CONTEXT_CONTROL
    };

    if (!GetThreadContext(hThread, &cThreadContext)) {
        printf("Could not get thread context, error: %d\n", GetLastError());
        return -1;
    }

    cThreadContext.Rip = (DWORD64) &UnsafeFunction;
    if (!SetThreadContext(hThread, &cThreadContext)) {
		printf("Could not set thread context, error: %d\n", GetLastError());
		return -1;
	}

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}


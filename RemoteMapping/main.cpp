#include <windows.h>
#include <stdio.h>
#include <memoryapi.h>

const unsigned char payload[] = "\x48\x48\x64\x64";

typedef PVOID (WINAPI* pMapViewOfFile2)(
  HANDLE  FileMappingHandle,
  HANDLE  ProcessHandle,
  ULONG64 Offset,
  PVOID   BaseAddress,
  SIZE_T  ViewSize,
  ULONG   AllocationType,
  ULONG   PageProtection
);

int main(int argc, char* argv[]) {

    HMODULE hmodKernel32 = LoadLibraryW(L"Kernel32.dll");
    if (hmodKernel32 == NULL) {
        printf("Could not load library, error: %d", GetLastError());
        return -1;
    }
    pMapViewOfFile2 myMapViewOfFile2 = (pMapViewOfFile2) GetProcAddress(hmodKernel32, "MapViewOfFile2");
    if (myMapViewOfFile2 == NULL) {
        printf("Could not get proc address, error: %d", GetLastError());
        return -1;
    }



    HANDLE file_handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(payload), NULL);
    LPVOID buffer = MapViewOfFile(file_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(payload));
    memcpy(buffer, payload, sizeof(payload));

    printf("Local buffer address: 0x%0.8X", buffer);

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));

    PVOID remote_buffer = myMapViewOfFile2(file_handle, process_handle, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE);

    printf("Remote buffer address: 0x%0.8X", remote_buffer);

    return 0;
}
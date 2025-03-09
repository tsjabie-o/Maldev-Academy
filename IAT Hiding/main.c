#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define KERNEL32DLLHASH 0xCC296063
#define GETCOMPUTERNAMEAHASH 0x523A7C05

typedef BOOL (WINAPI* fnGetComputerNameA)(
  LPSTR   lpBuffer,
  LPDWORD nSize
);

UINT32 Hasher(_In_ LPCSTR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = strlen(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

UINT32 HasherL(_In_ LPCWSTR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = wcslen(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

PVOID CustomGetProcAddress(PBYTE pBase, unsigned int functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] DOS Header signature does not match. Exiting.\n");
        return 0;
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS) (pBase + (dosHeader->e_lfanew));
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] NT Header signature does not match. Exiting.\n");
        return 0;
    }
    IMAGE_OPTIONAL_HEADER optHeader = ntHeader->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD functionNameTable = (PDWORD) (pBase + exportDir->AddressOfNames);
    PDWORD functionAddressTable = (PDWORD) (pBase + exportDir->AddressOfFunctions);
    PWORD functionOrdinalTable = (PWORD) (pBase + exportDir->AddressOfNameOrdinals);

    for (int i = 0; i < exportDir->NumberOfFunctions; i++)
    {
        char* functionName2 = (char*) (pBase + functionNameTable[i]);
        if (Hasher(functionName2) == functionHash) {
            WORD functionOrdinal = functionOrdinalTable[i];
            PVOID functionAddress = (PVOID) (pBase + functionAddressTable[functionOrdinal]);

            printf("Function name: %s\tAddress: 0x%0.8X\tOrdinal: %d\n", functionName2, functionAddress, functionOrdinal);
            return functionAddress;
        }
    }

    printf("Could not find function\n");
    return 0;
}

PBYTE CustomGetModuleHandle(unsigned int ModuleHash) {
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PLIST_ENTRY pListHead = &(pPEB->Ldr->InMemoryOrderModuleList);
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead)
    {
        PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY) pListEntry;
        if (HasherL(pDataTableEntry->FullDllName.Buffer) == ModuleHash) {
            PBYTE dllBase = (PBYTE) pDataTableEntry->Reserved2[0];
            return dllBase;
        }

        pListEntry = pListEntry->Flink;
    }
    
    printf("Could not find module with that name\n");
    return 0;
}

int main() {
    PBYTE hModule = CustomGetModuleHandle(KERNEL32DLLHASH);
    if (hModule == 0) {
        return -1;
    }

    PBYTE pBase = (PBYTE) hModule;

    fnGetComputerNameA myGetComputerNameA = (fnGetComputerNameA) CustomGetProcAddress(pBase, GETCOMPUTERNAMEAHASH);
    if (myGetComputerNameA == 0) {
        return -1;
    }

    printf("Performing function now...\n.\n.\n.\n");
    DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    myGetComputerNameA(buffer, &length);
    printf("Computer name: %s\n", buffer);
    return 0;
}
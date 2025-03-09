#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

const char* filename = "pe_file.exe";

BOOL GetFile(char** buffer, long* filesize) {
    FILE* file;
    size_t bytesRead;

    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file\n");
        return FALSE;
    }

    fseek(file, 0, SEEK_END);
    *filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (char*)malloc(*filesize);
    bytesRead = fread(*buffer, 1, *filesize, file);
    if (bytesRead != *filesize) {
        perror("Could not read file correctly. Buffer freed.\n");
        free(*buffer);
        fclose(file);
        return FALSE;
    }

    return TRUE;
}

BOOL ParseFileHeader(PIMAGE_FILE_HEADER pFileHeader) {
    printf("\n#### FILE HEADER ####\n");

    switch (pFileHeader->Machine) {
        case IMAGE_FILE_MACHINE_AMD64:
            printf("[+] Machine: x64\n");
            break;
        
        default:
            printf("[+] Machine: 0x%X (Could not match machine architecture)\n", pFileHeader->Machine);
            break;
    }

    printf("[+] Number of sections: %d\n", pFileHeader->NumberOfSections);


    struct tm* time_info;
    time_t seconds = pFileHeader->TimeDateStamp;
    time_info = gmtime(&seconds);
    char buffer[100];
    strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", time_info);
    printf("[+] Compilation timestamp: %s\n", buffer);

    return TRUE;
}

int main() {
    long filesize;
    char* buffer;

    if (!GetFile(&buffer, &filesize)) {
        return -1;
    }

    printf("\n#### DOS HEADER ####\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid PE file, DOS signature does not match.\n");
        goto _CLEANUP;
    }
    
    printf("[+] DOS MAGIC NUMBER: 0x%X\t\t(MZ)\n", pDosHeader->e_magic);

    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(buffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid PE file, NT signature does not match\n");
        goto _CLEANUP;
    }

    PIMAGE_FILE_HEADER pFileHeader = &(pNtHeaders->FileHeader);
    if (!ParseFileHeader(pFileHeader)) {
        goto _CLEANUP;
    }

    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64) &(pNtHeaders->OptionalHeader);
    if (pOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("Not a valid PE file, Optional Header signature does not match\n");
        goto _CLEANUP;
    }

    // PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (buffer + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (buffer + 0x9000);
    
    char* importName = buffer + pImportDescriptor->Name;
    printf("[+] First import name: %s", importName);

    _CLEANUP:
        free(buffer);
        return 0;
}
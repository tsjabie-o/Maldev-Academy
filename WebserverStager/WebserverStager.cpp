#include <stdio.h>
#include <Windows.h>
#include <Wininet.h>

#pragma comment (lib, "Wininet.lib")

#define P_LASTERROR(msg) \
    do { \
        printf("[!]\t%s\tError: %lu\n", (msg), GetLastError()); \
    } while (0)

#define PINFO(msg) \
    do { \
        printf("[-]\t%s"); \
    } while (0);

int main()
{
    // Establish connection

    HINTERNET hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        P_LASTERROR("Could not open Internet handle");
        return -1;
    }

    HINTERNET hUrl = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/message.bin", NULL, 0, (INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID), NULL);
    if (hUrl == NULL) {
        P_LASTERROR("Could not open url handle");
        return -1;
    }

    // Read the file into a buffer dynamically

    PBYTE pBuffer = (PBYTE)malloc(1024);
    PBYTE pTmpBuffer = (PBYTE)malloc(1024);
    DWORD dwBytesRead;
    SIZE_T sTotalSize = 0;

    while (TRUE)
    {
        if (!InternetReadFile(hUrl, pTmpBuffer, 1024, &dwBytesRead)) {
            P_LASTERROR("Could not read file");
            return -1;
        }
        
        pBuffer = (PBYTE)realloc(pBuffer, sTotalSize + dwBytesRead);

        if (pBuffer == NULL) {
            printf("No more space to reallocate");
            return -1;
        }

        memcpy(pBuffer + sTotalSize, pTmpBuffer, dwBytesRead);
        memset(pTmpBuffer, '\0', 1024);

        sTotalSize += dwBytesRead;

        if (dwBytesRead < 1024) {
            break;
        }
    }

    // Close the connection
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

    // Free temp buffer
    free(pTmpBuffer);

    // Do something with the bytes

    for (size_t i = 0, c = 1; i < sTotalSize; i++, c++)
    {
        printf("%0.2X  ", pBuffer[i]);
        if (c == 8) {
            printf("\n");
            c = 0;
        }
    }

    // Free the buffer
    free(pBuffer);

    return 0;
}

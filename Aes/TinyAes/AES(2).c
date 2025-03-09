// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

#define KEYSIZE				32
#define IVSIZE				16

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}


// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}



// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer	= NULL;
	SIZE_T	PaddedSize		= NULL;

	// Calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// Allocating buffer of size PaddedSize
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer){
		return FALSE;
	}
	// Cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// Saving results
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

// DECRYPTION //

unsigned char pKey[] = {
		0x00, 0xB8, 0x80, 0x7E, 0xF0, 0x09, 0x65, 0x8B, 0xD6, 0x6E, 0x2D, 0x8B, 0x0C, 0x6A, 0xA2, 0x34,
		0x42, 0x7A, 0x9D, 0x06, 0xC5, 0x48, 0x6E, 0x22, 0x01, 0x21, 0x7D, 0x5F, 0x44, 0xA9, 0x32, 0x9B };


unsigned char pIv[] = {
		0x00, 0xB8, 0x80, 0x7E, 0xF0, 0x09, 0x65, 0x8B, 0xD6, 0x6E, 0x2D, 0x8B, 0x0C, 0x6A, 0xA2, 0x34 };


unsigned char CipherText[] = {
		0xB9, 0x49, 0x12, 0x36, 0xFC, 0xAD, 0x15, 0xDA, 0x27, 0xA2, 0x02, 0xD4, 0x77, 0x8B, 0xBB, 0x4E,
		0xDA, 0xE5, 0x60, 0x71, 0x2F, 0xF4, 0x69, 0x2D, 0x9C, 0x12, 0x8D, 0xD0, 0xA3, 0x0E, 0xB7, 0x26,
		0x21, 0xE4, 0xA4, 0xAD, 0xB3, 0x05, 0xD9, 0x13, 0x8D, 0x2B, 0x0E, 0x0C, 0x21, 0x85, 0xD1, 0xC4,
		0xC1, 0x5A, 0x5F, 0x64, 0xDA, 0x1B, 0xB4, 0x7A, 0x7E, 0x6B, 0xE6, 0x80, 0x17, 0x28, 0x43, 0x4E,
		0xA6, 0x0A, 0x40, 0xB8, 0xBB, 0x1E, 0x27, 0x6A, 0x29, 0xE4, 0x5A, 0xA5, 0x4A, 0x4C, 0xB0, 0xA3,
		0x7D, 0x7A, 0x4E, 0x6D, 0x48, 0x86, 0xEB, 0xB2, 0xFD, 0x1B, 0x21, 0x89, 0xB0, 0x83, 0x14, 0xFE };


int main() {
	// Struct needed for tiny-AES library
	struct AES_ctx ctx;
	// Initilizing the Tiny-Aes Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));

	// Printing the decrypted buffer to the console
	PrintHexData("PlainText", CipherText, sizeof(CipherText));

	// Printing the string
	printf("Data: %s \n", CipherText);


	// Exit
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}


// ENCRYPTION //
/*
// "this is plain text sting, we'll try to encrypt... lets hope everythign go well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};



int main() {
	// Struct needed for tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[KEYSIZE];				// KEYSIZE is 32
	BYTE pIv[IVSIZE];				// IVSIZE is 16
		

	srand(time(NULL));				// The seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);		// Generating the key bytes

	srand(time(NULL) ^ pKey[0]);			// The seed to generate the iv (using the first byte from the key to add more spice)
	GenerateRandomBytes(pIv, IVSIZE);		// Generating the IV

	// Printing key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initilizing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address and its size in case padding is required
	PBYTE	PaddedBuffer	= NULL;
	SIZE_T	PAddedSize		= NULL;

	// Padding buffer, if needed
	if (sizeof(Data) % 16 != 0){
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	else {
		// No padding is required, encrypt Data directly
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}


	// Freeing PaddedBuffer, if needed
	if (PaddedBuffer != NULL){
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;

}
*/
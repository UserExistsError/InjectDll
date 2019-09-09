#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

/*
convert binary file to C array
*/

BOOL ReadFileData(WCHAR *filename, BYTE **buff, DWORD *size);
const IMAGE_NT_HEADERS* GetNtHeader(const BYTE* image, const DWORD imageSize);


BOOL WriteFileData(HANDLE hFile, BYTE *data, DWORD size)
{
	if (data == NULL)
		return FALSE;
	DWORD numWritten = 0;
	while (size > 0) {
		if (!WriteFile(hFile, data, size, &numWritten, NULL))
			return FALSE;
		data += numWritten;
		size -= numWritten;
	}
	return TRUE;
}

int wmain(int argc, WCHAR *argv[])
{
	if (argc < 4) {
		wprintf(L"usage: ExtractArray.exe <PEFILE> <NAME> <ARRAY.C>\n");
		return 1;
	}

	DWORD imageSize = 0;
	BYTE *image = NULL;
	if (!ReadFileData(argv[1], &image, &imageSize)) {
		wprintf(L"Failed to read file: %s\n", argv[1]);
		return 1;
	}

	// get .text section
	const IMAGE_NT_HEADERS *ntHeader = GetNtHeader(image, imageSize);
	if (ntHeader == NULL)
		return 1;

	IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(ntHeader);
	IMAGE_SECTION_HEADER *codeSection = NULL;
	for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
		if ((BYTE*)section > (image + imageSize - sizeof(IMAGE_SECTION_HEADER))) {
			wprintf(L"Invalid section header\n");
			return 1;
		}
		if (memcmp(".text\x00", section->Name, 6) == 0) {
			codeSection = section;
			break;
		}
	}
	if (codeSection == NULL) {
		wprintf(L"Failed to find code section\n");
		return 1;
	}

	// write .text section to file
	const BYTE *text = image + codeSection->PointerToRawData;
	if (text < image) {
		wprintf(L"Invalid .text section\n");
		return 1;
	}
	if ((text + codeSection->Misc.VirtualSize < text) || (text + codeSection->Misc.VirtualSize) > (image + imageSize)) {
		wprintf(L"Invalid .text section\n");
		return 1;
	}
	HANDLE hFile = CreateFileW(argv[3], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to open file: %s\n", argv[3]);
		return 1;
	}

	char buff[256+1];
	sprintf_s(buff, 256,
		"#pragma once\r\n"
		"const unsigned char %S[] = {\r\n",
		argv[2]);
	WriteFileData(hFile, (BYTE*)buff, lstrlenA(buff));
	for (size_t i = 0; i < codeSection->Misc.VirtualSize; i++) {
		if ((i % 16 == 0) && i)
			WriteFileData(hFile, (BYTE*)"\r\n", 2);
		sprintf_s(buff, 256, "0x%02x, ", text[i]);
		WriteFileData(hFile, (BYTE*)buff, lstrlenA(buff));
	}
	WriteFileData(hFile, (BYTE*)"\r\n};", 4);
	//wprintf(L"Wrote %lu bytes to %s\n", codeSection->Misc.VirtualSize, argv[3]);
	return 0;
}

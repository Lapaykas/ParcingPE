// Parcing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// ParcingPE.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Windows.h"
#include "atlbase.h"
#include "PARCINGPE.h"
#include <vector>
#include <utility>
#include <array>

int main()
{
	PIMAGE_SECTION_HEADER importSection = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;
	

	//ATL::CHandle FileHandle(CreateFileA("D:\\FlashScan.exe", FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	PARCINGPE PE("D:\\FlashScan.exe");
	PE.Parcing();
	LPVOID pMapFile = PE.GetPointerOfFile();
	// IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER dosHeader = PE.GetPointerDosHeader();
	//PE.PrintDosHeader();
	// IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS64 imageNTHeaders = PE.GetPointerNtHeader();
	//PE.PrintNtHeader();
	
	

	// SECTION_HEADERS
	printf("\n******* SECTION HEADERS *******\n");
	// get offset to first section headeer
	BYTE* pOffsetToSectionsHeaders = PE.GetPointerSectionsHeaders();
	BYTE sectionSize = sizeof(IMAGE_SECTION_HEADER);	
	

	std::vector<PIMAGE_SECTION_HEADER> vectorOfPointersToSections(15, nullptr);
	
	
	
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)pOffsetToSectionsHeaders;
		printf("\t%s\n", sectionHeader->Name);
		
		for (int j = 0; j < 15; j++)
		{
			DWORD directoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[j].VirtualAddress;
			if (directoryRVA >= sectionHeader->VirtualAddress && directoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)
			{
				vectorOfPointersToSections[j] = sectionHeader;
			}
		}
		pOffsetToSectionsHeaders += sectionSize;
	}

	BYTE* offsetToImportSection = (BYTE*)pMapFile + vectorOfPointersToSections[1]->PointerToRawData;

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(offsetToImportSection +
		(imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - vectorOfPointersToSections[1]->VirtualAddress));

	printf("\n******* DLL IMPORTS *******\n");
	for (; importDescriptor->Name != 0; importDescriptor++)
	{
		printf("\t%s\n", offsetToImportSection + (importDescriptor->Name - vectorOfPointersToSections[1]->VirtualAddress));
		ULONGLONG thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (PIMAGE_THUNK_DATA)(offsetToImportSection + (thunk - vectorOfPointersToSections[1]->VirtualAddress));
		
		for (; thunkData->u1.AddressOfData != 0; thunkData++)
		{
			printf("\t\t%s\n", (offsetToImportSection + (thunkData->u1.AddressOfData - vectorOfPointersToSections[1]->VirtualAddress+2)));
		}
	}
	
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file



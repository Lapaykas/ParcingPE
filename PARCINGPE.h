#pragma once
#include <windows.h>
#include "atlbase.h"
#include <vector>
class PARCINGPE
{
public:
	PARCINGPE(LPCSTR PATH);	
	~PARCINGPE();

	bool Parcing();
	LPVOID GetPointerOfFile();
	PIMAGE_DOS_HEADER GetPointerDosHeader();
	PIMAGE_NT_HEADERS64 GetPointerNtHeader();
	BYTE*  GetPointerSectionsHeaders();

	void PrintDosHeader();
	void PrintNtHeader();
private:
	LPVOID m_pMapFile;
	BYTE* m_pSectionsHeaders;

	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS64 m_pNtHeader;



	std::vector<PIMAGE_SECTION_HEADER> vectorOfPointersToSections;
	std::vector<BYTE*> vectorOfRAWToSections;
	void CreatePointerDosHeader();
	void CreatePointerNtHeader();
	void CreatePointerSectionsHeaders();
	void CreateRWAOfDirectories();
	void CreateVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector);
};


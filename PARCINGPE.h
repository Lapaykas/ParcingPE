#pragma once
#include <windows.h>
#include "atlbase.h"
#include <vector>
class PARCINGPE
{
public:
	PARCINGPE(LPCSTR PATH);	
	~PARCINGPE();

	void PrintDosHeader();
	void PrintNtHeader();
	void PrintSectionHeader();


	void PrintExportDirectory();
	void PrintImportDirectory();


private:
	//Указатель на начало файла
	LPVOID m_pMapFile;
	//Смещение до заголовков секций 
	BYTE* m_pSectionsHeaders;
	//Указатель на DOS - заголовок
	PIMAGE_DOS_HEADER m_pDosHeader;
	//Указатель на PE - заголовок
	PIMAGE_NT_HEADERS64 m_pNtHeader;

	//Вектор указателей на секции, соответствующие директориям
	std::vector<PIMAGE_SECTION_HEADER> m_vectorOfPointersToSections;
	//Вектор смещений от начала файла до директорий 
	std::vector<BYTE*> m_vectorOfRAWToSections;
	//Inline функция расчета смещения до нужно поля от начала файла
	inline LPBYTE GetOffsetToDataFromFile(PIMAGE_SECTION_HEADER pSectionHeader, DWORD rva);
	//Функция парснига PE - файла
	void Parcing();
	void GetPointerDosHeader();
	void GetPointerNtHeader();
	void GetPointerSectionsHeaders();
	void GetRWAOfDirectories();
	void GetVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector);
};


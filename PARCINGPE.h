#pragma once
#include <windows.h>
#include "atlbase.h"
#include <vector>
#include "Common.h"
class ParcingPeFile
{
public:
	ParcingPeFile(LPCSTR PATH);	
	~ParcingPeFile();

	void PrintDosHeader();
	void PrintNtHeader();
	void PrintSectionHeader();


	void PrintExportDirectory();
	void PrintImportDirectory();


private://смешал все в кучу. И функции и переменные
	//Указатель на начало файла
	LPVOID m_pMapFile;
	//Размер файла
	LONGLONG sizeOfFile;
	//Смещение до заголовков секций 
	LPBYTE m_pSectionsHeaders;
	//Указатель на DOS - заголовок
	PIMAGE_DOS_HEADER m_pDosHeader;
	//Указатель на PE - заголовок
	PIMAGE_NT_HEADERS64 m_pNtHeader;

	//вспомогательные функции
	//шаблонная функция получения смещения от начала файла
	template <typename T>
	T GetOffsetFromFile(size_t moveDistance) const noexcept;
	//шаблонная функция для проверки на выход за границу файла
	template <typename T>
	void CheckOutRangeOfFile(const T offset) const;

	//Вектор указателей на секции, соответствующие директориям
	std::vector<PIMAGE_SECTION_HEADER> m_vectorOfPointersToSections;
	//Вектор смещений от начала файла до директорий 
	std::vector<BYTE*> m_vectorOfRAWToSections;
	//Inline функция расчета смещения до нужно поля от начала файла
	inline LPBYTE GetOffsetToDataFromFile(PIMAGE_SECTION_HEADER pSectionHeader, DWORD rva);
	//Функция парснига PE - файла
	void GetPointersToSectionsAndHeaders();
	void GetPointerDosHeader();
	void GetPointerNtHeader();
	void GetPointerSectionsHeaders();
	void GetRWAOfDirectories();
	void GetVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector);
};

template<typename T>
T ParcingPeFile::GetOffsetFromFile(size_t moveDistance) const noexcept //Почему от файла? И главное, смещение ли это?
{
	return reinterpret_cast<T>(static_cast<LPBYTE>(m_pMapFile) + moveDistance);
}

template<typename T>
 void ParcingPeFile::CheckOutRangeOfFile(const T offset) const //плохое имя
{
	 if (static_cast<size_t>(offset) > sizeOfFile)
	 {
		 ERRORINFO(" File out of bounds"); //Файл все границ? ЗБС
	 }
}

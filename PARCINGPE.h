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


private://������ ��� � ����. � ������� � ����������
	//��������� �� ������ �����
	LPVOID m_pMapFile;
	//������ �����
	LONGLONG sizeOfFile;
	//�������� �� ���������� ������ 
	LPBYTE m_pSectionsHeaders;
	//��������� �� DOS - ���������
	PIMAGE_DOS_HEADER m_pDosHeader;
	//��������� �� PE - ���������
	PIMAGE_NT_HEADERS64 m_pNtHeader;

	//��������������� �������
	//��������� ������� ��������� �������� �� ������ �����
	template <typename T>
	T GetOffsetFromFile(size_t moveDistance) const noexcept;
	//��������� ������� ��� �������� �� ����� �� ������� �����
	template <typename T>
	void CheckOutRangeOfFile(const T offset) const;

	//������ ���������� �� ������, ��������������� �����������
	std::vector<PIMAGE_SECTION_HEADER> m_vectorOfPointersToSections;
	//������ �������� �� ������ ����� �� ���������� 
	std::vector<BYTE*> m_vectorOfRAWToSections;
	//Inline ������� ������� �������� �� ����� ���� �� ������ �����
	inline LPBYTE GetOffsetToDataFromFile(PIMAGE_SECTION_HEADER pSectionHeader, DWORD rva);
	//������� �������� PE - �����
	void GetPointersToSectionsAndHeaders();
	void GetPointerDosHeader();
	void GetPointerNtHeader();
	void GetPointerSectionsHeaders();
	void GetRWAOfDirectories();
	void GetVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector);
};

template<typename T>
T ParcingPeFile::GetOffsetFromFile(size_t moveDistance) const noexcept //������ �� �����? � �������, �������� �� ���?
{
	return reinterpret_cast<T>(static_cast<LPBYTE>(m_pMapFile) + moveDistance);
}

template<typename T>
 void ParcingPeFile::CheckOutRangeOfFile(const T offset) const //������ ���
{
	 if (static_cast<size_t>(offset) > sizeOfFile)
	 {
		 ERRORINFO(" File out of bounds"); //���� ��� ������? ���
	 }
}

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
	void PrintImportDirectory();

private:
	//��������� �� ������ �����
	LPVOID m_pMapFile;
	//�������� �� ���������� ������ 
	BYTE* m_pSectionsHeaders;
	//��������� �� DOS - ���������
	PIMAGE_DOS_HEADER m_pDosHeader;
	//��������� �� PE - ���������
	PIMAGE_NT_HEADERS64 m_pNtHeader;

	//������ ���������� �� ������, ��������������� �����������
	std::vector<PIMAGE_SECTION_HEADER> m_vectorOfPointersToSections;
	//������ �������� �� ������ ����� �� ���������� 
	std::vector<BYTE*> m_vectorOfRAWToSections;

	//������� �������� PE - �����
	void Parcing();
	void GetPointerDosHeader();
	void GetPointerNtHeader();
	void GetPointerSectionsHeaders();
	void GetRWAOfDirectories();
	void GetVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector);
};


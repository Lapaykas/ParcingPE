// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "PARCINGPE.h"
#include <string>
//Логично тут сделать шаблонную функцию AddToPtr, которая двигаети любой указательна смещение и возвращает указатель на что-то. //добавил(исправил)

//Что за имя класса из больших букв?! 
//исправил
//хреново исправил, ParcingPeFile - это процесс. А не некая сущность
ParcingPeFile::ParcingPeFile(LPCSTR pathToPE) : m_pDosHeader(nullptr), m_pNtHeader(nullptr), m_pMapFile(nullptr), m_pSectionsHeaders(nullptr),
							m_vectorOfPointersToSections(IMAGE_NUMBEROF_DIRECTORY_ENTRIES, nullptr), 
							m_vectorOfRAWToSections(IMAGE_NUMBEROF_DIRECTORY_ENTRIES, nullptr), sizeOfFile(0)
{
	ATL::CHandle FileHandle(CreateFileA(pathToPE, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	if ((FileHandle == INVALID_HANDLE_VALUE) && (FileHandle==0))//эта проверка все еще нихуя не работает! подумай как проверить!
	{
		ERRORINFO("Could not read file");
	}
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(FileHandle, &fileSize))
	{
		ERRORINFO("Could not get size of file");
		
	}
	sizeOfFile = fileSize.QuadPart;
	ATL::CHandle MapFileHandle(CreateFileMapping(FileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr));
	if (MapFileHandle == INVALID_HANDLE_VALUE)
	{
		ERRORINFO("Could not create file mapping");
	}
	
	m_pMapFile = MapViewOfFile(MapFileHandle, FILE_MAP_READ, 0, 0, 0);
	if (m_pMapFile == nullptr)
	{
		ERRORINFO("Could not map view of file");
	}

	GetPointersToSectionsAndHeaders();
}


ParcingPeFile::~ParcingPeFile()
{
	UnmapViewOfFile(m_pMapFile);
}




void ParcingPeFile::GetPointersToSectionsAndHeaders()
{
	GetPointerDosHeader();
	GetPointerNtHeader();
	GetPointerSectionsHeaders();
	GetRWAOfDirectories();
}

void ParcingPeFile::PrintDosHeader()
{
	printf("******* DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", m_pDosHeader->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", m_pDosHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", m_pDosHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", m_pDosHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", m_pDosHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", m_pDosHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", m_pDosHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", m_pDosHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", m_pDosHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", m_pDosHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", m_pDosHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", m_pDosHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", m_pDosHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", m_pDosHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", m_pDosHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", m_pDosHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", m_pDosHeader->e_lfanew);
}

void ParcingPeFile::PrintNtHeader()
{
printf("\n******* NT HEADERS *******\n");
	printf("\t%x\t\tSignature\n", m_pNtHeader->Signature);


	// FILE_HEADER
	printf("\n******* FILE HEADER *******\n");
	printf("\t0x%x\t\tMachine\n", m_pNtHeader->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", m_pNtHeader->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", m_pNtHeader->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", m_pNtHeader->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", m_pNtHeader->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", m_pNtHeader->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", m_pNtHeader->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\n******* OPTIONAL HEADER *******\n");
	printf("\t0x%x\t\tMagic\n", m_pNtHeader->OptionalHeader.Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", m_pNtHeader->OptionalHeader.MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", m_pNtHeader->OptionalHeader.MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", m_pNtHeader->OptionalHeader.SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", m_pNtHeader->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", m_pNtHeader->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", m_pNtHeader->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", m_pNtHeader->OptionalHeader.BaseOfCode);
	//printf("\t0x%x\t\tBase Of Data\n", imageNTHeaders->OptionalHeader.BaseOfData);
	printf("\t0x%x\t\tImage Base\n", m_pNtHeader->OptionalHeader.ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", m_pNtHeader->OptionalHeader.SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", m_pNtHeader->OptionalHeader.FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", m_pNtHeader->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", m_pNtHeader->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", m_pNtHeader->OptionalHeader.MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", m_pNtHeader->OptionalHeader.MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", m_pNtHeader->OptionalHeader.MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", m_pNtHeader->OptionalHeader.MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", m_pNtHeader->OptionalHeader.Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", m_pNtHeader->OptionalHeader.SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", m_pNtHeader->OptionalHeader.SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", m_pNtHeader->OptionalHeader.CheckSum);
	printf("\t0x%x\t\tSubsystem\n", m_pNtHeader->OptionalHeader.Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", m_pNtHeader->OptionalHeader.DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", m_pNtHeader->OptionalHeader.SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", m_pNtHeader->OptionalHeader.SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", m_pNtHeader->OptionalHeader.SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", m_pNtHeader->OptionalHeader.SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", m_pNtHeader->OptionalHeader.LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", m_pNtHeader->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("\tResource Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	printf("\tException Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	printf("\tSecurity Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	printf("\tBaseReloc Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	printf("\tDebug Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	printf("\tArchitecture Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
	printf("\tGlobalPtr Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
	printf("\tTLS Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	printf("\tLoadConfig Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	printf("\tBoundImport Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	printf("\tIAT Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	printf("\tDelayImport Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	printf("\tComDescriptor Directory Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);
	printf("\tUNKNOWN DIRECTORY Address: 0x%x; Size: 0x%x\n", m_pNtHeader->OptionalHeader.DataDirectory[15].VirtualAddress, m_pNtHeader->OptionalHeader.DataDirectory[15].Size);
}

void ParcingPeFile::PrintSectionHeader()
{
	BYTE* pStartOfSections = m_pSectionsHeaders;
	BYTE sectionSize = sizeof(IMAGE_SECTION_HEADER);
	printf("\n******* SECTION HEADERS *******\n");
	for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; i++) 
	{
		PIMAGE_SECTION_HEADER sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pStartOfSections); //разъименование нулевого указателя
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);		
		pStartOfSections += sectionSize;
	}
}

void ParcingPeFile::PrintExportDirectory()
{	
	//хуйня какая-то.
	/*  ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⣀⠄⠄⠄⠄⡀⠄⠄⡀⠠⣤⣄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⠉⢉⡏⠄⠄⠄⢸⡇⠄⣼⠇⠄⢀⡏⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⣧⡤⣤⡀⠈⠓⠚⣿⠄⠄⣸⠳⠶⢶⡀⠄⠄
		⠄⠄⠄⠄⣀⡀⠄⠄⠄⠄⠄⠄⣿⠁⠄⣸⡇⣀⣠⡴⠟⠄⠄⣿⣀⣀⣼⠇⠄⠄
		⠄⣠⣶⣿⣿⣿⣿⠆⠄⠄⠄⠄⠻⠦⠶⠋⠄⠉⠄⠄⠄⠄⠄⠉⠉⠉⠁⠄⠄⠄
		⢰⣿⣿⡿⠛⠉⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⢸⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⣀⣠⣤⣀⣀⠄⠄⠄⠄⢀⣀⣀⣀⡀⠄⠄
		⠄⢿⣿⣧⠄⠄⠄⠄⠄⠄⢀⣴⣿⣿⣿⣿⣿⣿⣿⣷⣄⠄⣼⣿⣿⣿⣿⣿⣦⠄
		⠄⠘⣿⣿⣧⡀⠄⠄⠄⢠⣾⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⡀⠹⠿⠛⠉⢹⣿⣿⡄
		⠄⠄⠈⢿⣿⣿⣄⠄⢠⣿⣿⣿⣇⣍⢹⣿⣯⣰⣼⣿⡿⠁⠄⠄⠄⢀⣾⣿⣿⠃
		⠄⠄⠄⠈⢿⣿⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠁⠄⠄⢀⣴⣾⣿⡿⠃⠄
		⠄⠄⠄⠄⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣤⣶⣿⣿⣿⠟⠋⠄⠄⠄
		⠄⠄⠄⠄⠄⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⠋⠉⠉⠉⠘⣿⣿⣿⣿⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿⡏⠄⠄⠄⠄⠄⢹⣿⣿⣿⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿⡇⠄⠄⠄⠄⠄⠸⣿⣿⣿⡄⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⣿⣿⣿⣿⠄⠄⠄⠄⠄⠄⠄⣿⣿⣿⣷⠄⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿⡆⠄⠄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⢰⣿⣿⣿⣄⠄⠄⠄⠄⠄⠄⠄⠈⣿⣿⣿⣿⣶⡄⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠈⠻⣿⣿⡟⠄⠄⠄⠄⠄⠄⠄⠄⢿⣿⣿⣿⠿⠃⠄⠄⠄⠄⠄⠄
		⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄*/

	PIMAGE_SECTION_HEADER pExportSection = m_vectorOfPointersToSections[0]; //Магические числа!
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(m_vectorOfRAWToSections[0]);
	LPDWORD pNameTable = (LPDWORD)GetOffsetToDataFromFile(pExportSection, pExportDirectory->AddressOfNames);//reinterpret
	printf("\n******* DLL EXPORTS *******\n");
	printf("%s\n", reinterpret_cast<char*>(GetOffsetToDataFromFile(pExportSection,pExportDirectory->Name))); //функция не коррелирует со своим названием
	for (UINT i = 0; i < pExportDirectory->NumberOfNames; i++) {
	
		printf("\t%s\n", reinterpret_cast<char*>(GetOffsetToDataFromFile(pExportSection, pNameTable[i])));
	}
  }

void ParcingPeFile::PrintImportDirectory()
{
	PIMAGE_SECTION_HEADER pImportSection = m_vectorOfPointersToSections[1];
	printf("\n******* DLL IMPORTS *******\n");	
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_vectorOfRAWToSections[1]);
	for (; pImportDirectory->Name != 0; pImportDirectory++) //разименование nullptr!
	{
		printf("\t%s\n", pImportSection->Name); //можно и так
		ULONGLONG thunk = pImportDirectory->OriginalFirstThunk == 0 ? pImportDirectory->FirstThunk : pImportDirectory->OriginalFirstThunk;
		PIMAGE_THUNK_DATA thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(GetOffsetToDataFromFile(pImportSection, thunk));
		for (; thunkData->u1.AddressOfData != 0; thunkData++)
		{
			printf("\t\t%s\n", reinterpret_cast<char*>(GetOffsetToDataFromFile(pImportSection, thunkData->u1.AddressOfData+2))); //что за 2?
		}//а еще тут падает на бинаре винрара. УПС.
	}
}



void ParcingPeFile::GetPointerDosHeader()
{
	m_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(m_pMapFile);
}

void ParcingPeFile::GetPointerNtHeader()
{
	CheckOutRangeOfFile(m_pDosHeader->e_lfanew);	
	m_pNtHeader = GetOffsetFromFile<PIMAGE_NT_HEADERS64>(m_pDosHeader->e_lfanew);
	//TODO: организовать проверки на не выход за границу файла	//исправил
}

void ParcingPeFile::GetPointerSectionsHeaders()
{
	const size_t offset = static_cast<LONGLONG>(m_pDosHeader->e_lfanew) + sizeof(_IMAGE_NT_HEADERS64);//что за offset? до чего?
	CheckOutRangeOfFile(offset);
	m_pSectionsHeaders = GetOffsetFromFile<LPBYTE>(offset);
}

void ParcingPeFile::GetRWAOfDirectories()
{
	BYTE* pStartOfSections = m_pSectionsHeaders; //некорректное имя, не соответствует назначению
	if (pStartOfSections == nullptr)
	{
		ERRORINFO("No directrories in PE file"); //может ли быть такое в корректном exe?
	}
	constexpr BYTE sectionSize = sizeof(IMAGE_SECTION_HEADER); //имя не правильно
	for (int i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; i++) //signed/unsigned
	{
		PIMAGE_SECTION_HEADER pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(pStartOfSections);
		const DWORD sectionStart = pSectionHeader->VirtualAddress;//проверки, потенциально разименование nullptr //конст //исправил
		const DWORD sectionEnd = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;//конст //исправил
		//а надо ли вообще что-то делать, если начало и конец секции nullptr?
		for (int j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++) //Кто такой 15?// исправил
		{
			const DWORD directoryRVA = m_pNtHeader->OptionalHeader.DataDirectory[j].VirtualAddress; //Это точно Relative адрес?
			if (directoryRVA >= sectionStart && directoryRVA < sectionEnd)
			{
				m_vectorOfPointersToSections[j] = pSectionHeader;
			}
		}
		pStartOfSections += sectionSize;
	}
	GetVectorOfRWA(m_vectorOfPointersToSections);
}

void ParcingPeFile::GetVectorOfRWA(std::vector<PIMAGE_SECTION_HEADER>& argVector)
{
	for (auto i=0ull; i< argVector.size(); i++)
	{
		// тут можн обойтись contionue и уменьшить число скобочек или тернарным оператором // исправил
		if (argVector[i] == nullptr)
		{
			continue;
		}		
		//pFirstPageCOFFFile - что это такое и почему в каждой итерации оно называется первый!
		LPBYTE pFirstPageCOFFFile = MovePointer(static_cast<LPBYTE>(m_pMapFile), argVector[i]->PointerToRawData); //А нахрена писать функцию, что бы потом все равно кастить указатель???
		auto _4to_za_hernia = m_pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress - argVector[i]->VirtualAddress; //!!!!!!
		LPBYTE pRAWtoSection = MovePointer(pFirstPageCOFFFile, _4to_za_hernia);
		m_vectorOfRAWToSections[i] = pRAWtoSection;		
	}
}



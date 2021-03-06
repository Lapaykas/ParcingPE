// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <iostream>
#include "Windows.h"
#include "atlbase.h"
#include "PARCINGPE.h"
#include <vector>
#include <utility>
#include <array>

int main()
{
	try {
		ParcingPeFile PE("C:\\Program Files\\WinRAR\\WinRar.exe");

		PE.PrintDosHeader();

		PE.PrintNtHeader();

		PE.PrintSectionHeader();

		PE.PrintImportDirectory();
		PE.PrintExportDirectory();
	}
	catch (const std::exception &e)
	{
		std::cout << e.what() << std::endl;
	}
}

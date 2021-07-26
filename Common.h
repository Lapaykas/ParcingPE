#pragma once
#include "windows.h"

#define ERRORINFO(errorMessage) \
do{ \
char error[256]; \
sprintf_s(error, 256,"%s %s %d %s", __FILE__ ,__FUNCTION__, __LINE__, errorMessage); \
throw std::exception(error);}\
while(0);

inline LPBYTE MovePointer(LPBYTE pStartPosition, DWORD offset) noexcept
{
	return pStartPosition + offset;
}
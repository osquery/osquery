
#include "osquery\tables\utility\file_windows_ops.h"

namespace osquery {


	/*
		These functions were adapted from the Microsoft Windows Classic Samples (MIT License)
		https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/winbase/io/extendedfileapis/ExtendedFileAPIs.cpp
	*/

	std::string getFileAttribStr(ULONG FileAttributes)
	{

		// Attributes Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/gg258117

		std::string attribs;

		if (FileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
			// Archive file attribute
			attribs.push_back('A');
			FileAttributes &= ~FILE_ATTRIBUTE_ARCHIVE;
		}
		if (FileAttributes & FILE_ATTRIBUTE_COMPRESSED) {
			// Compressed (Not included in attrib.exe output)
			attribs.push_back('C');
			FileAttributes &= ~FILE_ATTRIBUTE_COMPRESSED;
		}
		if (FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) {
			// Encrypted (Not included in attrib.exe output)
			attribs.push_back('E');
			FileAttributes &= ~FILE_ATTRIBUTE_ENCRYPTED;
		}
		if (FileAttributes & FILE_ATTRIBUTE_HIDDEN) {
			// Hidden file attribute
			attribs.push_back('H');
			FileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
		}
		if (FileAttributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) {
			// 
			attribs.push_back('V');
			FileAttributes &= ~FILE_ATTRIBUTE_INTEGRITY_STREAM;
		}
		if (FileAttributes & FILE_ATTRIBUTE_NORMAL) {
			// Normal (Not included in attrib.exe output)
			attribs.push_back('N');
			FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
		}
		if (FileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
			// Not content indexed file attribute
			attribs.push_back('I');
			FileAttributes &= ~FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
		}
		if (FileAttributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) {
			// No scrub file attribute
			attribs.push_back('X');
			FileAttributes &= ~FILE_ATTRIBUTE_NO_SCRUB_DATA;
		}
		if (FileAttributes & FILE_ATTRIBUTE_OFFLINE) {
			// Offline attribute
			attribs.push_back('O');
			FileAttributes &= ~FILE_ATTRIBUTE_OFFLINE;
		}
		if (FileAttributes & FILE_ATTRIBUTE_READONLY) {
			// Read-only file attribute
			attribs.push_back('R');
			FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
		}
		if (FileAttributes & FILE_ATTRIBUTE_SYSTEM) {
			// System file attribute
			attribs.push_back('S');
			FileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
		}
		if (FileAttributes & FILE_ATTRIBUTE_TEMPORARY) {
			// Temporary file attribute (Not included in attrib.exe output)
			attribs.push_back('T');
			FileAttributes &= ~FILE_ATTRIBUTE_TEMPORARY;
		}
		
		/*
		 NOTE:  The following are included in attrib.exe output as of Win 8/10, but docs are limited
		 P   Pinned attribute.
		 U   Unpinned attribute.
		*/

		return attribs;

	}

	time_t LongIntToUnixTime(LARGE_INTEGER & ft)
	{
		ULARGE_INTEGER ull;

		ull.LowPart = ft.LowPart;
		ull.HighPart = ft.HighPart;

		return ull.QuadPart / 10000000ULL - 11644473600ULL;
	}

	time_t FileTimeToUnixTime(FILETIME & ft)
	{
		ULARGE_INTEGER ull;

		ull.LowPart = ft.dwLowDateTime;
		ull.HighPart = ft.dwHighDateTime;

		return ull.QuadPart / 10000000ULL - 11644473600ULL;
	}


	


}
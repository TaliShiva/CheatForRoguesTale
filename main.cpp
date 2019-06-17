#include "Windows.h"
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <vector>

DWORD dwBufferSize = 1024 * 1024;
uint64_t ullPlayerSeg = 0xE9000180D8D7E700;

/*
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}
BOOL EnableDebugPrivilages()
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	return SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
}*/

class MemoryRegion
{
public:
	PVOID BaseAddress ;
	unsigned int RegionSize;
	DWORD Protect;
	
};



std::vector<MemoryRegion> QueryMemoryRegions(HANDLE processHandle) {
	LPVOID curr = 0;
	MEMORY_BASIC_INFORMATION memInfo = {};
	std::vector<MemoryRegion> regions{};
	while (true) {
		try {
			auto memDump = VirtualQueryEx(processHandle, curr, &memInfo, dwBufferSize);
			if (memDump == 0)
			{
				break;
			}
			if ((memInfo.State & 0x1000) != 0 && (memInfo.Protect & 0x100) == 0)
			{
				MemoryRegion reg;
				reg.BaseAddress = memInfo.BaseAddress;
				reg.RegionSize = memInfo.RegionSize;
				reg.Protect = memInfo.Protect;
				regions.push_back(reg);
				//printf("RegionSize: %lu;\n  ProtectType: %lu;\n", reg.RegionSize, reg.Protect);
			}
			curr = (LPVOID)(reinterpret_cast<DWORD>(memInfo.BaseAddress) + (DWORD)(memInfo.RegionSize));

			PBYTE pBuffer = new BYTE[memInfo.RegionSize];
			PBYTE pCurByte = pBuffer;
			PBYTE pEndOfBuf = pBuffer + memInfo.RegionSize;
			BOOL bRes = ReadProcessMemory(processHandle, memInfo.BaseAddress, &pBuffer, memInfo.RegionSize, 0);
			if(bRes == 0 || memInfo.RegionSize == 0)
			{
				printf("Error ReadprocessMemory %u\n", GetLastError());
				delete[] pBuffer;
				continue;
			}
			while(pCurByte < pEndOfBuf-8) // 8 - длина ключевого слова
			{
				if(ullPlayerSeg == *reinterpret_cast<uint64_t*>(pCurByte))
				{
					DWORD dwHealth = *reinterpret_cast<DWORD*>(pCurByte + 8 + 29);
					printf("Structure checked, Player Health %lu", dwHealth);
				}
				pCurByte++;
			}

			delete[] pBuffer;
					}
		catch (...){
			break;
		}
	}
	return regions;
}

int main()
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	
	if (Process32First(snapshot, &entry) == TRUE)
	{
		
		while (Process32Next(snapshot, &entry) == TRUE)
		{
		//	EnableDebugPrivilages();
			if (_stricmp(entry.szExeFile, "Rogue.exe") == 0)
			{
				printf("ProcessID: %lu;\n", entry.th32ProcessID);
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				if(hProcess == NULL)
				{
					printf("Open process was wrong: %u\n", GetLastError());
				}
				QueryMemoryRegions(hProcess);

				CloseHandle(hProcess);
			}
		}
	}

	CloseHandle(snapshot);
	system("PAUSE");
	return 0;
}
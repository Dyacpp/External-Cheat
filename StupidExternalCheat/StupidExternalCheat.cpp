#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

DWORD GetProcessID(const char* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32First(snapshot, &processEntry)) {
            do {
                if (_stricmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }

    return processId;
}
//
// returns a vector of base addresses for memory regions that are read/write 
// in the specified process.
//
std::vector<LPVOID> GetReadWriteMemoryRegions(HANDLE Process)
{
    std::vector<LPVOID> readWriteRegions;

    HANDLE hProcess = Process;
    if (hProcess == NULL)
    {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return readWriteRegions; // returns empty on failure
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // starting address for enumeration
    LPVOID currentAddress = sysInfo.lpMinimumApplicationAddress;

    while (currentAddress < sysInfo.lpMaximumApplicationAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T bytesReturned = VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi));
        if (bytesReturned == 0)
        {
            // could not query this region, move on
            currentAddress = (LPBYTE)currentAddress + 0x1000; // 1 page step
            continue;
        }

        // check if this region is committed and has any read-write permissions
        if (mbi.State == MEM_COMMIT)
        {
            // common read-write protection constants:
            // - PAGE_READWRITE
            DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
            switch (prot)
            {
            case PAGE_READWRITE:
                readWriteRegions.push_back(mbi.BaseAddress); // skibidi
                break;
            default:
                break;
            }
        }

        // move to the next region. 
        // add RegionSize to the base address to get the next region start.
        currentAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    return readWriteRegions;
}

struct StringMatch
{
    int address;  // the address in the target process's memory where the string was found
    size_t length;   // the length of the matched string (just for reference)
};

std::vector<StringMatch> scanMemoryForString(BYTE* buffer, const char* name, int length) {
    std::vector<StringMatch> matches;
    SIZE_T scanSize = length;
    SIZE_T sigLen = strlen(name);

    // search for the signature in the buffer (naive approach)
    for (SIZE_T i = 0; i + sigLen <= scanSize; i++)
    {
        // compare the memory at buffer[i..i+sigLen)
        if (memcmp(buffer + i, name, sigLen) == 0)
        {
            StringMatch match;
            match.address = i;
            match.length = sigLen;
            matches.push_back(match);
        }
    }

    return matches;
}

int main() {
    SIZE_T BytesRead = 0;
    HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, GetProcessID("MazeClient.exe"));
    std::vector<LPVOID> MemoryAddresses = GetReadWriteMemoryRegions(ProcessHandle);
    UINT64 UserNameAddress = 0;
    for (auto& base : MemoryAddresses) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T bytesReturned = VirtualQueryEx(ProcessHandle, base, &mbi, sizeof(mbi)); // checks page size
        if (bytesReturned == 0)
        {
            DWORD error = GetLastError();
            //std::cout << error << std::endl;
            continue;
        }
        BYTE* buffer = new BYTE[mbi.RegionSize]; // 2mb --> heap
        ReadProcessMemory(ProcessHandle, base, buffer, mbi.RegionSize, &BytesRead);
        std::vector<StringMatch> matches = scanMemoryForString(buffer, "supernigger", BytesRead);
        delete[] buffer;
        if (matches.empty()) {
            continue;
        }
        else {
            //std::cout << std::hex << (UINT64)base + matches[0].address << std::endl;
            UserNameAddress = (UINT64)base + matches[0].address;
            UINT64 SpeedAddress = UserNameAddress - 0x8; // playerbase - 0x168 + 0x160
            float speed;
            ReadProcessMemory(ProcessHandle, (LPVOID)SpeedAddress, &speed, sizeof(float), NULL);
            if (speed > 299 && speed < 2500) {
                //std::cout << "This is the speed address: " << SpeedAddress << std::endl;
                float SpeedToWrite = 2499;
                int StupidScore = 500000;
                SIZE_T BytesWritten = 0;
                int merdus = WriteProcessMemory(ProcessHandle, (LPVOID)SpeedAddress, &SpeedToWrite, sizeof(float), &BytesWritten);
                break;
            }
        }
    }
}

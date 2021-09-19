# Wumbobfuscating API Hooking Techniques
The C/C++ code exemplifying the API Hooking techniques below was originally written by [Sektor7 Institute](https://institute.sektor7.net/) within their [Malware Development Intermediate](https://institute.sektor7.net/courses/rto-maldev-intermediate) course. The explanations and analysis of the code are entirely my own.

## Background
API Hooking is a method of changing the behavior of an application by intercepting a process in-memory. Although API Hooking it is used for legitimate purposes across the Windows OS, it is also leveraged by implants.

API Hooking is defined in the MITRE ATT&CK Framework as [T1056.004](https://attack.mitre.org/techniques/T1056/004/), where it is listed as a subtechnique of Input Capture. The MITRE ATT&CK Framework does not assign subtechniques to different API Hooking implementations. This repository will refer to different implementations of API Hooking as techniques.

## Detours
Detour API Hooking intercepts Win32 functions by redirecting a legitimate function call to a **detour function**. This **detour function** rewrites the in-process binary image of the target function, and may attach an arbitrary Dynamic Link Library (DLL) or payload to the process. A **trampoline function** is then used to redirect control to execution of the legitimate functions.

### Detour API Hooking Stages
##### Hooking
1. [`DetourTransactionBegin()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionBegin) - Begin a new transaction for attaching a detour.
2. [`DetourUpdateThread`](https://github.com/Microsoft/Detours/wiki/DetourUpdateThread) - Update the target with a pending transaction.
3. [`DetourAttach()`](https://github.com/Microsoft/Detours/wiki/DetourAttach) or [`DetourAttachEx()`](https://github.com/Microsoft/Detours/wiki/DetourAttachEx) - Attach a detour to a target function.
4. [`DetourTransactionCommit()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionCommit) or [`DetourTransactionCommitEx()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionCommitEx) - Used by the target program to commit to the detour. The previous two steps do not take place until the program has committed to the detour transaction this way.
##### Unhooking
5. [`DetourTransactionBegin()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionBegin) - Begin a new transaction for detaching detours.
6. [`DetourUpdateThread`](https://github.com/Microsoft/Detours/wiki/DetourUpdateThread) - Update the target thread with a pending transaction.
7. [`DetourDettach()`](https://github.com/Microsoft/Detours/wiki/DetourAttach) or [`DetourDettachEx()`](https://github.com/Microsoft/Detours/wiki/DetourAttachEx) - Detach a detour to a target function.
8. [`DetourTransactionCommit()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionCommit) or [`DetourTransactionCommitEx()`](https://github.com/Microsoft/Detours/wiki/DetourTransactionCommitEx) - Used by the target program to commit to the detour. The previous two steps do not take place until the program has committed to the detour transaction this way.
 
A more detailed description of these functions can be found in Microsoft's [`Detours`](https://github.com/microsoft/Detours) GitHub repository.

### x86 Example
A stack-based example of API Hooking in x86 is as follows:

Before Detours API Hooking has taken place, the target function (`Target_Function`) contains legitimate instructions. When targeted, these instructions will be copied to a **trampoline function** so that the program resumes normal execution after API Hooking has taken place. Until that occurs, the **trampoline function** will contain only a `jmp` instruction to the target function.

```asm
Target_Function:   ; Legitimate Function
  push ebp
  mov ebp, esp
  push ebx
  push esi
  push edi
 ```
 
 ```asm
Trampoline_Function:
  jmp Target_Function
```

After Detours API Hooking has taken place, the target function (`Target_Function`) will contain a `jmp` instruction to the **detour function**. The **trampoline function** will execute the original instructions from the target function, before passing back control to a specific offset of the target function where its original final instructions reside.

```asm
Target_Function:
  jmp Detour_Function
```

```asm
Target_Function+5:
  push edi
```

```asm
Trampoline_Function:
  push ebp
  mov ebp, esp
  push ebx
  push esi
  jmp Target_Function+5
```

## Developing Detour API Hooking Techniques
#### Dependencies
```c++
#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")
```

#### Implementation
In the Detours API Hooking code exemplified here, the [`DLLMain()`](https://docs.microsoft.com/en-us/previous-versions/ms939455(v=msdn.10)) function uses a switch-case statement to determine different conditions based on the [`dwReason`](https://docs.microsoft.com/en-us/previous-versions/ms939455(v=msdn.10)), the condition of why the DLL entry-point function is being called.

- `DLL_PROCESS_ATTACH` - The DLL is being loaded into a process starting or as a result of a call to `LoadLibrary()`, and the process can be targeted by hook via a custom `Hook()`function.
- `DLL_THREAD_ATTACH` - The current process is creating a new thread, and there is not an opportunity for Detour API Hooking and the program disregards the case.
- `DLL_THREAD_DETACH` - The current process is detaching an existing thread, and there is not an opportunity for Detour API Hooking and the program disregards the case.
- `DLL_PROCESS_DETACH` - The DLL is being unloaded from the calling process, and the process should be unhooked via a custom `Unhook()` function.

```c++
// Credit: reenz0h (@sektor7net), RTO Malware Development Essentials course

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hook();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			Unhook();
			break;
	}
	
    return TRUE;
}
```


#### Hooking

```c++
// pointer to original MessageBox
int (WINAPI * pOrigMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;
BOOL Hook(void);
BOOL Unhook(void);

// Hooking function
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	
	printf("HookedMessageBox() called. No popup on screen!\n");
	
	return IDOK;
}

// Set hooks on MessageBox
BOOL Hook(void) {

    LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
	err = DetourTransactionCommit();

	printf("MessageBox() hooked! (res = %d)\n", err);
	
	return TRUE;
}
```

#### Unhooking

```c++
// Revert all changes to original code
BOOL Unhook(void) {
	
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
	err = DetourTransactionCommit();

	printf("Hook removed from MessageBox() with result = %d\n", err);
	
	return TRUE;
}
```

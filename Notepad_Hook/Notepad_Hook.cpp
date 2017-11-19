#include <tchar.h>
#include <easyhook.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include <WinNT.h>

DWORD gFreqOffset = 0;
NTSTATUS NtCreateFileHook(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
){
	MessageBox(GetActiveWindow(), (LPCWSTR)ObjectAttributes->ObjectName->Buffer,(LPCWSTR)L"Object Name", MB_OK);
	return NtCreateFile(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,
		CreateDisposition,CreateOptions,EaBuffer,EaLength);
}

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	
	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	// Install the hook
	NTSTATUS result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtCreateFile"),
		NtCreateFileHook,
		NULL,
		&hHook);
	if (FAILED(result))
	{
		MessageBox(GetActiveWindow(), (LPCWSTR)RtlGetLastErrorString(), (LPCWSTR)L"Failed to install hook", MB_OK);
	}

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}


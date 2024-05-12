#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#define NT_SUCCESS(x) ((x) >= 0)

PVOID ProcAddress;

#define NTSTATUS long

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

PVOID FindBaseAddress(ULONG pid) {
	HINSTANCE hNtDLL = NULL;
	PSYSTEM_HANDLE_INFORMATION buffer;
	ULONG bufferSize = 0xffffff;
	NTSTATUS status;
	_NtQuerySystemInformation pNtQuerySystemInformation;
	int i = 0;

	long long int startcycle = 0;
	long long int endcycle = 0;


	hNtDLL = LoadLibraryA("ntdll.dll");
	buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
	

	pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtDLL, "NtQuerySystemInformation");

	// 1
	startcycle = __rdtsc();

	status = pNtQuerySystemInformation(0x10, buffer, bufferSize, NULL); // 0x10 = SystemHandleInformation
	if (!NT_SUCCESS(status)) {
		printf("NTQueryInformation Failed!\n");
		exit(-1);
	}

	endcycle = __rdtsc();

	printf("startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	// 2
	startcycle = __rdtsc();

	status = pNtQuerySystemInformation(0x10, buffer, bufferSize, NULL); // 0x10 = SystemHandleInformation
	if (!NT_SUCCESS(status)) {
		printf("NTQueryInformation Failed!\n");
		exit(-1);
	}

	endcycle = __rdtsc();

	printf("startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	printf("now load hypervisor, press ENTER to continue\n");
	getchar();

	// 3
	startcycle = __rdtsc();

	status = pNtQuerySystemInformation(0x10, buffer, bufferSize, NULL); // 0x10 = SystemHandleInformation
	if (!NT_SUCCESS(status)) {
		printf("NTQueryInformation Failed!\n");
		exit(-1);
	}

	endcycle = __rdtsc();

	printf("startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	for (i = 0; i <= buffer->HandleCount; i++) {
		if ((buffer->Handles[i].ProcessId == pid)) { 
			ProcAddress = buffer->Handles[i].Object;
			printf("Address: 0x%p, Object Type: %d, Handle: %x\n", buffer->Handles[i].Object, buffer->Handles[i].ObjectTypeNumber, buffer->Handles[i].Handle);
		}

	}
	free(buffer);
}

void main()

{
	printf("NTQuerySystemInformation() PoC -- Bruno Oliveira @mphx2\n");
	FindBaseAddress(GetCurrentProcessId());
	//getchar();
}
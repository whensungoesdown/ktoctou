#include <stdio.h>
#include <stdlib.h>

#define _X86_

//
// Start with NTDDK.H
//
#include <ntddk.h>


NTSYSCALLAPI NTSTATUS NTAPI NtCreateSection(
  PHANDLE            SectionHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PLARGE_INTEGER     MaximumSize,
  ULONG              SectionPageProtection,
  ULONG              AllocationAttributes,
  HANDLE             FileHandle
);

NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
  HANDLE          SectionHandle,
  HANDLE          ProcessHandle,
  PVOID           *BaseAddress,
  ULONG_PTR       ZeroBits,
  SIZE_T          CommitSize,
  PLARGE_INTEGER  SectionOffset,
  PSIZE_T         ViewSize,
  SECTION_INHERIT InheritDisposition,
  ULONG           AllocationType,
  ULONG           Win32Protect
);

NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
  HANDLE ProcessHandle,
  PVOID  BaseAddress
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(HANDLE Handle);

int test_ntcreatesection (void)
{
	HANDLE hSection;
	OBJECT_ATTRIBUTES secAttr;
	LARGE_INTEGER size;
	NTSTATUS status;
	PVOID address = NULL;
	SIZE_T viewSize = 0;

	long long int startcycle = 0;
	long long int endcycle = 0;


	InitializeObjectAttributes(&secAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	
	size.QuadPart = 1 << 13;	// 8KB

	startcycle = __rdtsc();

	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, 
		&secAttr, &size, PAGE_READWRITE, SEC_COMMIT, NULL);

	endcycle = __rdtsc();
	printf("NtCreateSection startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	if (!NT_SUCCESS(status)) {
		printf("Failed to create/open section (0x%X)\n", status);
		return status;
	}

	startcycle = __rdtsc();

	status = NtMapViewOfSection(hSection, NtCurrentProcess(), &address, 
		0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

	endcycle = __rdtsc();
	printf("NtMapViewOfSection startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	if (!NT_SUCCESS(status)) {
		printf("Failed to map section (0x%X)\n", status);
		return status;
	}

	printf("NtMapViewOfSection, map to address 0x%x\n", address);


	startcycle = __rdtsc();

	NtUnmapViewOfSection(NtCurrentProcess(), address);

	endcycle = __rdtsc();
	printf("NtUnmapViewOfSection startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);


	NtClose(hSection);

	return 0;
}

int main() 
{
	int i = 0;

	printf("press ENTER to start\n");
	getchar();

	for (i = 0; i < 100000; i++)
	{
		;
	}

	for (i = 0; i < 8; i++)
	{
		test_ntcreatesection();
	}


	printf("now load hypervisor, press ENTER to continue\n");
	getchar();


	for (i = 0; i < 100000; i++)
	{
		;
	}

	for (i = 0; i < 8; i++)
	{
		test_ntcreatesection();
	}

	return 0;
}
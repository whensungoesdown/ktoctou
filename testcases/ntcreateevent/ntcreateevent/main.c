#include <stdio.h>
#include <stdlib.h>

#define _X86_

//
// Start with NTDDK.H
//
#include <ntddk.h>

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(
  PHANDLE            EventHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  EVENT_TYPE         EventType,
  BOOLEAN            InitialState
);

NTSYSAPI NTSTATUS NTAPI NtSetEvent(
  HANDLE EventHandle,
  PLONG  PreviousState
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(HANDLE Handle);

int test_ntcreateevent (void)
{
	OBJECT_ATTRIBUTES evtAttr;
	HANDLE hEvent;
	NTSTATUS status;

	long long int startcycle = 0;
	long long int endcycle = 0;



	InitializeObjectAttributes(&evtAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	

	startcycle = __rdtsc();

	status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &evtAttr, SynchronizationEvent, FALSE);
	endcycle = __rdtsc();
	printf("NtCreateEvent startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	if (!NT_SUCCESS(status)) {
		printf("Failed to create/open event (0x%X)\n", status);
		return status;
	}

	startcycle = __rdtsc();

	status = NtSetEvent(hEvent, NULL);

	endcycle = __rdtsc();
	printf("NtSetEvent startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	if (!NT_SUCCESS(status)) {
		printf("NtSetEvent failed (0x%X)\n", status);
		return status;
	}

	NtClose(hEvent);

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
		test_ntcreateevent();
	}


	printf("now load hypervisor, press ENTER to continue\n");
	getchar();


	for (i = 0; i < 100000; i++)
	{
		;
	}

	for (i = 0; i < 8; i++)
	{
		test_ntcreateevent();
	}

	return 0;
}
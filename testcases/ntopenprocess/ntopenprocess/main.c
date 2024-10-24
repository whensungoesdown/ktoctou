#include <stdio.h>
#include <stdlib.h>

#define _X86_

//
// Start with NTDDK.H
//
#include <ntddk.h>


#pragma comment(lib, "ntdll")

#define PROCESS_TERMINATE		0x0001

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess(
  HANDLE   ProcessHandle,
  NTSTATUS ExitStatus
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(HANDLE Handle);


//#define DWORD ULONG
//#define WORD short
//#define LPBYTE char*
//
//typedef struct _CURDIR
//{
//    UNICODE_STRING DosPath;
//    HANDLE Handle;
//} CURDIR, *PCURDIR;
//
//typedef struct _RTL_DRIVE_LETTER_CURDIR
//{
//    USHORT Flags;
//    USHORT Length;
//    ULONG TimeStamp;
//    STRING DosPath;
//} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
//
//#define RTL_MAX_DRIVE_LETTERS 32
//
//typedef struct _RTL_USER_PROCESS_PARAMETERS
//{
//    ULONG MaximumLength;
//    ULONG Length;
//
//    ULONG Flags;
//    ULONG DebugFlags;
//
//    HANDLE ConsoleHandle;
//    ULONG ConsoleFlags;
//    HANDLE StandardInput;
//    HANDLE StandardOutput;
//    HANDLE StandardError;
//
//    CURDIR CurrentDirectory;
//    UNICODE_STRING DllPath;
//    UNICODE_STRING ImagePathName;
//    UNICODE_STRING CommandLine;
//    PVOID Environment;
//
//    ULONG StartingX;
//    ULONG StartingY;
//    ULONG CountX;
//    ULONG CountY;
//    ULONG CountCharsX;
//    ULONG CountCharsY;
//    ULONG FillAttribute;
//
//    ULONG WindowFlags;
//    ULONG ShowWindowFlags;
//    UNICODE_STRING WindowTitle;
//    UNICODE_STRING DesktopInfo;
//    UNICODE_STRING ShellInfo;
//    UNICODE_STRING RuntimeData;
//    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
//
//    ULONG_PTR EnvironmentSize;
//    ULONG_PTR EnvironmentVersion;
//
//    PVOID PackageDependencyData;
//    ULONG ProcessGroupId;
//    ULONG LoaderThreads;
//    UNICODE_STRING RedirectionDllName; // REDSTONE4
//    UNICODE_STRING HeapPartitionName; // 19H1
//    PULONGLONG DefaultThreadpoolCpuSetMasks;
//    ULONG DefaultThreadpoolCpuSetMaskCount;
//    ULONG DefaultThreadpoolThreadMaximum;
//    ULONG HeapMemoryTypeMask; // WIN11
//} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
//
//// symbols
//typedef struct _SECTION_IMAGE_INFORMATION
//{
//    PVOID TransferAddress;
//    ULONG ZeroBits;
//    SIZE_T MaximumStackSize;
//    SIZE_T CommittedStackSize;
//    ULONG SubSystemType;
//    union
//    {
//        struct
//        {
//            USHORT SubSystemMinorVersion;
//            USHORT SubSystemMajorVersion;
//        };
//        ULONG SubSystemVersion;
//    };
//    union
//    {
//        struct
//        {
//            USHORT MajorOperatingSystemVersion;
//            USHORT MinorOperatingSystemVersion;
//        };
//        ULONG OperatingSystemVersion;
//    };
//    USHORT ImageCharacteristics;
//    USHORT DllCharacteristics;
//    USHORT Machine;
//    BOOLEAN ImageContainsCode;
//    union
//    {
//        UCHAR ImageFlags;
//        struct
//        {
//            UCHAR ComPlusNativeReady : 1;
//            UCHAR ComPlusILOnly : 1;
//            UCHAR ImageDynamicallyRelocated : 1;
//            UCHAR ImageMappedFlat : 1;
//            UCHAR BaseBelow4gb : 1;
//            UCHAR ComPlusPrefer32bit : 1;
//            UCHAR Reserved : 2;
//        };
//    };
//    ULONG LoaderFlags;
//    ULONG ImageFileSize;
//    ULONG CheckSum;
//} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
//
//typedef struct _RTL_USER_PROCESS_INFORMATION
//{
//    ULONG Length;
//    HANDLE ProcessHandle;
//    HANDLE ThreadHandle;
//    CLIENT_ID ClientId;
//    SECTION_IMAGE_INFORMATION ImageInformation;
//} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;


NTSTATUS KillNative(ULONG pid) {
	OBJECT_ATTRIBUTES procAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(NULL, 0);
	CLIENT_ID cid = {0};	// zero-out structure
	
	HANDLE hProcess;
	NTSTATUS status;

	long long int startcycle = 0;
	long long int endcycle = 0;


	cid.UniqueProcess = ULongToHandle(pid);

	startcycle = __rdtsc();

	status = NtOpenProcess(&hProcess, PROCESS_TERMINATE, &procAttr, &cid);
	if (!NT_SUCCESS(status))
		return status;

	endcycle = __rdtsc();

	printf("NtOpenProcess startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);


	startcycle = __rdtsc();

	status = NtTerminateProcess(hProcess, 1);
	endcycle = __rdtsc();

	printf("NtTerminateProcess startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);


	startcycle = __rdtsc();
	NtClose(hProcess);
	endcycle = __rdtsc();

	printf("NtClose startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	return status;
}

//ULONG create_process()
//{
//	UNICODE_STRING cmdline;
//	UNICODE_STRING name;
//	PRTL_USER_PROCESS_PARAMETERS params;
//	NTSTATUS status;
//	RTL_USER_PROCESS_INFORMATION info;
//	ULONG pid;
//
//
//	RtlInitUnicodeString(&cmdline, L"\\??\\C:\\Windows\\notepad.exe");
//
//	
//	RtlInitUnicodeString(&name, L"\\??\\C:\\Windows\\notepad.exe");
//
//	
//	status = RtlCreateProcessParameters(&params, &name, NULL, NULL, &cmdline,
//		NULL, NULL, NULL, NULL, NULL);
//	if (!NT_SUCCESS(status))
//		return 0;
//
//	
//	status = RtlCreateUserProcess(&name, 0, params, NULL, NULL, NULL, 0, NULL, NULL, &info);
//	if (!NT_SUCCESS(status))
//		return 0;
//
//	RtlDestroyProcessParameters(params);
//
//	pid = HandleToULong(info.ClientId.UniqueProcess);
//
//
//	ResumeThread(info.ThreadHandle);
//
//	printf("Process 0x%X (%u) created successfully.\n", pid, pid);
//
//	CloseHandle(info.ThreadHandle);
//	CloseHandle(info.ProcessHandle);
//}

int main(int argc, const char* argv[]) 
{

	ULONG pid0 = 0;
	ULONG pid1 = 0;
	ULONG pid2 = 0;
	ULONG pid3 = 0;
	ULONG pid4 = 0;
	ULONG pid5 = 0;
	ULONG pid6 = 0;
	ULONG pid7 = 0;

	NTSTATUS status = 0;

	if (argc < 9) {
		printf("Usage: Kill <pid0> <pid1> <pid2> <pid3> <pid4> <pid5> <pid6> <pid7>\n");
		return 0;
	}

	pid0 = strtoul(argv[1], NULL, 0);
	pid1 = strtoul(argv[2], NULL, 0);
	pid2 = strtoul(argv[3], NULL, 0);
	pid3 = strtoul(argv[4], NULL, 0);
	pid4 = strtoul(argv[5], NULL, 0);
	pid5 = strtoul(argv[6], NULL, 0);
	pid6 = strtoul(argv[7], NULL, 0);
	pid7 = strtoul(argv[8], NULL, 0);


	//pid = create_process();

	//if (0 != pid)
	//{
	//	printf("create process notepad.exe succss, pid %d\n", pid);
	//}
	//else
	//{
	//	printf("create process notepad.exe failed, exit\n");
	//	return -1;
	//}

	printf("press ENTER to start\n");
	getchar();

	status = KillNative(pid0);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid0);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid1);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid1);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid2);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid2);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid3);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid4);
	else
		printf("Error: 0x%X\n", status);


	printf("now load hypervisor, press ENTER to continue\n");
	getchar();


	status = KillNative(pid4);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid4);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid5);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid5);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid6);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid6);
	else
		printf("Error: 0x%X\n", status);

	status = KillNative(pid7);
	if (NT_SUCCESS(status))
		printf("Kill %d Success!\n", pid7);
	else
		printf("Error: 0x%X\n", status);



	return 0;
}
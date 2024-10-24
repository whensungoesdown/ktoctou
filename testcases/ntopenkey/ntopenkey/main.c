#include <stdio.h>
#include <stdlib.h>

#define _X86_

//
// Start with NTDDK.H
//
#include <ntddk.h>

NTSYSAPI NTSTATUS NTAPI NtOpenKey(
  PHANDLE            KeyHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI NTSTATUS NTAPI NtEnumerateValueKey(
  HANDLE                      KeyHandle,
  ULONG                       Index,
  KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  PVOID                       KeyValueInformation,
  ULONG                       Length,
  PULONG                      ResultLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(HANDLE Handle);


//CHAR* RegistryTypeToString(DWORD type) 
//{
//	switch (type) {
//		case REG_SZ: return "REG_SZ";
//		case REG_DWORD: return "REG_DWORD";
//		case REG_MULTI_SZ: return "REG_MULTI_SZ";
//		case REG_QWORD: return "REG_QDWORD";
//		case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
//		case REG_NONE: return "REG_NONE";
//		case REG_LINK: return "REG_LINK";
//		case REG_BINARY: return "REG_BINARY";
//		case REG_RESOURCE_REQUIREMENTS_LIST: return "REG_RESOURCE_REQUIREMENTS_LIST";
//		case REG_RESOURCE_LIST: return "REG_RESOURCE_LIST";
//		case REG_FULL_RESOURCE_DESCRIPTOR: return "REG_FULL_RESOURCE_DESCRIPTOR";
//	}
//	return "<unknown>";
//}
//
//void DisplayData(KEY_VALUE_FULL_INFORMATION const* info) {
//	auto p = (PBYTE)info + info->DataOffset;
//	switch (info->Type) {
//		case REG_SZ:
//		case REG_EXPAND_SZ:
//			printf("%ws\n", (PCWSTR)p);
//			break;
//
//		case REG_MULTI_SZ:
//			{
//				auto s = (PCWSTR)p;
//				while (*s) {
//					printf("%ws ", s);
//					s += wcslen(s) + 1;
//				}
//				printf("\n");
//				break;
//			}
//
//		case REG_DWORD:
//			printf("%u (0x%X)\n", *(DWORD*)p, *(DWORD*)p);
//			break;
//
//		case REG_QWORD:
//			printf("%llu (0x%llX)\n", *(ULONGLONG*)p, *(ULONGLONG*)p);
//			break;
//
//		case REG_BINARY:
//		case REG_FULL_RESOURCE_DESCRIPTOR:
//		case REG_RESOURCE_LIST:
//		case REG_RESOURCE_REQUIREMENTS_LIST:
//			auto len = min(64, info->DataLength);
//			for (DWORD i = 0; i < len; i++) {
//				printf("%02X ", p[i]);
//			}
//			printf("\n");
//			break;
//	}
//}

NTSTATUS EnumerateKeyValues(HANDLE hKey) 
{
	ULONG len;
	NTSTATUS status;
	char buffer[10240] = {0};
	KEY_VALUE_FULL_INFORMATION* info = NULL;
	int i = 0;

	long long int startcycle = 0;
	long long int endcycle = 0;

	len = 10240;

	while (1)
	{
		startcycle = __rdtsc();
		status = NtEnumerateValueKey(hKey, i, KeyValueFullInformation, buffer, len, &len);
		endcycle = __rdtsc();

		printf("NtEnumerateValueKey startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

		//if (!NT_SUCCESS(status))
		//{
		//	printf("NtEnumerateValueKey fail 0x%x\n", status);
		//	break;
		//}

		
		info = (KEY_VALUE_FULL_INFORMATION*)buffer;

		//printf("Name: %ws Type: (%u) Data Size: %u bytes Data: \n",
		//	info->Name,
		//	//RegistryTypeToString(info->Type),
		//	info->Type,
		//	info->DataLength);

		//DisplayData(info);
		i++;


		break; // only enumerate one
	}
	return STATUS_SUCCESS;
}

int main(int argc, const char* argv[]) 
{
	HANDLE hKey;
	UNICODE_STRING keyName;
	OBJECT_ATTRIBUTES keyAttr;
	NTSTATUS status;
	int i = 0;

	long long int startcycle = 0;
	long long int endcycle = 0;


	RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\system\\select");
	InitializeObjectAttributes(&keyAttr, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	printf("press ENTER to start\n");
	getchar();

	for (i = 0; i < 100000; i++)
	{
		;
	}


	for (i = 0; i < 8; i++)
	{
		startcycle = __rdtsc();
		status = NtOpenKey(&hKey, KEY_QUERY_VALUE, &keyAttr);
		if (!NT_SUCCESS(status)) {
			printf("Failed to open key (0x%X)\n", status);
			return status;
		}
		endcycle = __rdtsc();

		printf("NtOpenKey startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);


		EnumerateKeyValues(hKey);
		NtClose(hKey);
	}


	printf("now load hypervisor, press ENTER to continue\n");
	getchar();

	for (i = 0; i < 100000; i++)
	{
		;
	}


	for (i = 0; i < 8; i++)
	{
		startcycle = __rdtsc();
		status = NtOpenKey(&hKey, KEY_QUERY_VALUE, &keyAttr);
		if (!NT_SUCCESS(status)) {
			printf("Failed to open key (0x%X)\n", status);
			return status;
		}
		endcycle = __rdtsc();

		printf("NtOpenKey startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);


		EnumerateKeyValues(hKey);
		NtClose(hKey);
	}
}
//++
//  Native.c 
//
//  Demonstration of using native NT API for File I/O
//
//  Accompanies the article "Going Native",in the Summer
//  1996 (V3N3) issue of The NT Insider
//
//  ntinsider@osr.com - http://www.osr.com
//
//  THIS SOFTWARE IS SUPPLIED "AS IS", AND EXPLICITLY
//  WITHOUT WARRANTY OF ANY KIND. See accompanying
//  file "readme.txt" which contains the full text
//  outlining the conditions under which this material
//  is made available.
//
// 
//  Environment:
//
//    User mode, NT api.
//
//--
#include <stdlib.h>
#include <stdio.h>

#define _X86_

//
// Start with NTDDK.H
//
#include <ntddk.h>

//
// Add the definitions for the native APIs we'll be using
//
#include "native.h"


int test_ntcreatefile (void)
{
	NTSTATUS Status;
    UNICODE_STRING UnicodeFilespec;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;
    IO_STATUS_BLOCK Iosb;
    //ULONG MessageLength = strlen(Message1);

	long long int startcycle = 0;
	long long int endcycle = 0;


    printf("Starting OSR's Native NT API Example...\n");

    //
    // Initialize a unicode string with the fully qualified path of the file
    // that we wish to create
    //
    RtlInitUnicodeString(&UnicodeFilespec, L"\\DosDevices\\C:\\test_ntcreatefile.txt");


    //
    // Setup the name in an object attributes structure.
    // Note that we create a name that is case INsensitive
    //
    InitializeObjectAttributes(&ObjectAttributes,           // ptr to structure
                               &UnicodeFilespec,            // ptr to file spec
                               OBJ_CASE_INSENSITIVE,        // attributes
                               NULL,                        // root directory handle
                               NULL );                      // ptr to security descriptor

	
	startcycle = __rdtsc();

    //
    // Do the create.  In this particular case, we'll have the I/O Manager
    // make our write requests syncrhonous for our convenience.
    //
    Status = NtCreateFile(&FileHandle,                      // returned file handle
                          (GENERIC_WRITE | SYNCHRONIZE),     // desired access
                          &ObjectAttributes,                // ptr to object attributes
                          &Iosb,                            // ptr to I/O status block
                          0,                                // allocation size
                          FILE_ATTRIBUTE_NORMAL,            // file attributes
                          0,                                // share access
                          FILE_SUPERSEDE,                   // create disposition
                          FILE_SYNCHRONOUS_IO_NONALERT,     // create options
                          NULL,                             // ptr to extended attributes
                          0);                               // length of ea buffer

	endcycle = __rdtsc();

	printf("startcycle %lld, endcycle %lld, %d\n", startcycle, endcycle, endcycle - startcycle);

	//
	// Check the system service status
	//
	if( !NT_SUCCESS(Status) )
	{
		printf("Create system service failed status = 0x%0x\n", Status);

		return -1;
	}


    //
    // Check the returned status too...
    //
	if(!NT_SUCCESS(Iosb.Status) )
	{
		printf("CREATE failed with status = 0x%0x\n",Iosb.Status);
		return -1;
	}


    //
    // Well, That's all folks!
    //
    Status = NtClose(FileHandle);


    //
    // If the CLOSE system service request fails, we're pretty hosed!
	//
	if(!NT_SUCCESS(Status) )
	{
		printf("NtClose request failed 0x%0x\n", Status);
		return -1;
	}


    printf("OSR's Native NT API example complete!\n");

    return 0;
}

//
// MAIN
//
int main (int Argc, char ** Argv )
{
	int i = 0;

	printf("press ENTER to start\n");
	getchar();

	for (i = 0; i < 8; i++)
	{
		test_ntcreatefile();
	}

	printf("now load hypervisor, press ENTER to continue\n");
	getchar();


	for (i = 0; i < 8; i++)
	{
		test_ntcreatefile();
	}

	return 0;
}

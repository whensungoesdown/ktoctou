//  [5/7/2015 uty]
#ifndef _VMXEXITHANDLER_H_
#define _VMXEXITHANDLER_H_
//-----------------------------------------------------------------------------//
typedef struct _GUEST_REGS
{
	ULONG eax;                  // 0x00         // NOT VALID FOR SVM
	ULONG ecx;
	ULONG edx;                  // 0x10
	ULONG ebx;
	ULONG esp;                  // 0x20         // rsp is not stored here on SVM
	ULONG ebp;
	ULONG esi;                  // 0x30
	ULONG edi;
	//ULONG64 r8;                   // 0x40
	//ULONG64 r9;
	//ULONG64 r10;                  // 0x50
	//ULONG64 r11;
	//ULONG64 r12;                  // 0x60
	//ULONG64 r13;
	//ULONG64 r14;                  // 0x70
	//ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;
//-----------------------------------------------------------------------------//
#endif
//  [5/5/2015 uty]
#include <ntddk.h>
#include "vmx.h"
#include "cpu.h"
#include "i386/vmx-asm.h"
#include "i386/common-asm.h"
#include "i386/regs-asm.h"
#include "vmxexithandler.h"
#include "ept.h"
#include "exceptionnmi.h"
#include "vmcall.h"
#include "smap.h"
#include "helper.h"
#include "structs.h"

extern ULONG g_VirtualAddress;
extern UCHAR g_OriByte;
extern ULONG g_TargetEprocess;

#define PTE_BASE 0xc0000000
#define MiGetPteAddress(va) ((PMMPTE)(((((ULONG)(va)) >> 12) << 3) + PTE_BASE))  // PAE 8 bytes
//-----------------------------------------------------------------------------//
VOID
ResumeToNextInstruction (
	VOID
	)
{
	PVOID pResumeRIP = NULL;
	PVOID pCurrentRIP = NULL;
	ULONG ulExitInstructionLength = 0;

	pCurrentRIP = (PVOID)VmxRead(GUEST_RIP);
	ulExitInstructionLength = (ULONG)VmxRead(VM_EXIT_INSTRUCTION_LEN);

	pResumeRIP = (PCHAR)pCurrentRIP + ulExitInstructionLength;

	VmxWrite(GUEST_RIP, (ULONG)pResumeRIP);
}
//-----------------------------------------------------------------------------//
VOID HandleNMI(VOID)
{
	ULONG trap;
	ULONG ExitInterruptionInformation = 0;
	ULONG eFlags = 0;


	//DbgPrint("HandleNMI!!!!!!!!!!!!!!!!!!!!!!\n");

	ExitInterruptionInformation = VmxRead(VM_EXIT_INTR_INFO);

	trap = ExitInterruptionInformation & INTR_INFO_VECTOR_MASK;

	switch (trap) 
	{
	case TRAP_PAGE_FAULT:
	case TRAP_INT3:
		{
			PVOID pCurrentRIP = NULL;
			ULONG ulTmp = 0;
			ULONG ulOldCr3 = 0;

			//__asm int 3;
			//DbgPrint("TRAP_INT3!!!!!!!!!!!!!!!!!!!! original byte 0x%x, IRQL 0x%x\n", g_OriByte, KeGetCurrentIrql());

			pCurrentRIP = (PVOID)VmxRead(GUEST_RIP);

			if (g_OriByte == (UCHAR)0xCC)
			{
				ResumeToNextInstruction();
				DbgPrint("TRAP_INT3 Original byte is cc, EIP 0x%x, skip\n", pCurrentRIP);
				return;
			}


			__asm
			{
				mov eax, cr3
				mov ulOldCr3, eax

				mov eax, g_TargetCr3
				mov cr3, eax
			}

			DisableWriteProtect();

			*(PUCHAR)pCurrentRIP = (UCHAR)g_OriByte;

			EnableWriteProtect();

			ReleasePage();

			__asm
			{
				mov eax, ulOldCr3
				mov cr3, eax
			}

			//DbgPrint("CR3 0x%x, EIP 0x%x, IRQL 0x%x\n", ulOldCr3, pCurrentRIP, KeGetCurrentIrql());
		}
		break;
	case TRAP_DEBUG:

		{
			//__asm int 3;
			DbgPrint("TRAP_DEBUG!!!!!!!!!!!!!!!!!!!!\n");

			//eFlags = RegGetEflags();
			eFlags = VmxRead(GUEST_RFLAGS);
			eFlags = eFlags & ~FLAGS_TF_MASK/* &  ~FLAGS_RF_MASK*/;
			VmxWrite(GUEST_RFLAGS, FLAGS_TO_ULONG(eFlags));

			ReleasePage();
			ReleaseSmapPages_Cr3_All();
		}
		break;
	default:
		/* Unhandled exception/nmi */
		//Log("Unexpected exception/NMI", trap);
		return;
	}
}
//-----------------------------------------------------------------------------//
VOID
HandleCPUID (
	__inout PGUEST_REGS GuestRegs
	)
{
	int cpuInfo[4] = {0};

	__cpuid(&cpuInfo, (int)GuestRegs->eax);

	GuestRegs->eax = (ULONG)cpuInfo[0];
	GuestRegs->ebx = (ULONG)cpuInfo[1];
	GuestRegs->ecx = (ULONG)cpuInfo[2];
	GuestRegs->edx = (ULONG)cpuInfo[3];
}
//-----------------------------------------------------------------------------//
VOID HandleINVLPG (VOID)
{
	//ULONG ExitQualification = 0;

	//ExitQualification = VmxRead(EXIT_QUALIFICATION);  // linear-address operand of invlpg

	//if (0 == ExitQualification)
	//{
	//	TestFlush();
	//}
	//else
	//{
	//	__asm
	//	{
	//		mov eax, ExitQualification
	//			invlpg [eax]
	//	}
	//}
}
//-----------------------------------------------------------------------------//
VOID
HandleCR (
	__inout PGUEST_REGS GuestRegs
	)
{
	ULONG movcrControlRegister = 0;
	ULONG movcrAccessType = 0;
	ULONG movcrOperandType = 0;
	ULONG movcrGeneralPurposeRegister = 0;

	ULONG ExitQualification = 0;
	ULONG GuestCR0 = 0;
	ULONG GuestCR3 = 0;
	ULONG GuestCR4 = 0;

	ULONG x = 0;

	ULONG ulEflags= 0;


	ExitQualification = VmxRead(EXIT_QUALIFICATION);
	GuestCR0 = VmxRead(GUEST_CR0);
	GuestCR3 = VmxRead(GUEST_CR3);
	GuestCR4 = VmxRead(GUEST_CR4);

	movcrControlRegister = (ULONG)(ExitQualification & 0x0000000F);
	movcrAccessType = (ULONG)((ExitQualification & 0x00000030) >> 4);
	movcrOperandType = (ULONG)((ExitQualification & 0x00000040) >> 6);
	movcrGeneralPurposeRegister = (ULONG)((ExitQualification & 0x00000F00) >> 8);


	/* Process the event (only for MOV CRx, REG instructions) */
	if (movcrOperandType == 0 && (movcrControlRegister == 0 || movcrControlRegister == 3 || movcrControlRegister == 4)) 
	{
		if (movcrAccessType == 0) 
		{
			/* CRx <-- reg32 */
			ULONG regval = 0;

			if (movcrControlRegister == 0) 
				x = GUEST_CR0;
			else if (movcrControlRegister == 3)
				x = GUEST_CR3;
			else
				x = GUEST_CR4;	  

			switch(movcrGeneralPurposeRegister) 
			{
			case 0: 
				{
					regval = GuestRegs->eax;
					VmxWrite(x, GuestRegs->eax);
				}
				break;
			case 1:  
				{
					regval = GuestRegs->ecx;
					VmxWrite(x, GuestRegs->ecx); 
				}
				break;
			case 2:  
				{
					regval = GuestRegs->edx;
					VmxWrite(x, GuestRegs->edx); 
				}
				break;
			case 3:  
				{
					regval = GuestRegs->ebx;
					VmxWrite(x, GuestRegs->ebx); 
				}
				break;
			case 4:  
				{
					regval = GuestRegs->esp;
					VmxWrite(x, GuestRegs->esp); 
				}
				break;
			case 5:  
				{
					regval = GuestRegs->ebp;
					VmxWrite(x, GuestRegs->ebp); 
				}
				break;
			case 6:  
				{
					regval = GuestRegs->esi;
					VmxWrite(x, GuestRegs->esi); 
				}
				break;
			case 7:  
				{
					regval = GuestRegs->edi;
					VmxWrite(x, GuestRegs->edi); 
				}
				break;
			default: 
				break;
			}

			if (regval == g_TargetCr3)
			{
				ULONG cr4 = 0;
				//ULONG cr0 = 0;

				//__asm int 3;

				cr4 = VmxRead(GUEST_CR4);
				cr4 = cr4 | 0x200000;
				VmxWrite(GUEST_CR4, cr4);

				//cr0 = VmxRead(GUEST_CR0);
				//cr0 = cr0 | 0x60000000; // Cache Disable (31) Not-write Through (30)
				//VmxWrite(GUEST_CR0, cr0);


				

				//__asm
				//{
				//	mov eax, ulEflags
				//	mov [ebp+0x3c], eax
				//}
			}
			else
			{
				ULONG cr4 = 0;
				//ULONG cr0 = 0;

				cr4 = VmxRead(GUEST_CR4);
				cr4 = cr4 & ~0x200000;
				VmxWrite(GUEST_CR4, cr4);

				//cr0 = VmxRead(GUEST_CR0);
				//cr0 = cr0 & ~0x60000000; // Cache Disable (31) Not-write Through (30)
				//VmxWrite(GUEST_CR0, cr0);
			}

			// uty: test

			//ulEflags = VmxRead(GUEST_RFLAGS);
			////ulEflags = RegGetEflags();

			//ulEflags = ulEflags | FLAGS_TF_MASK /*| FLAGS_RF_MASK*/;

			//VmxWrite(GUEST_RFLAGS, FLAGS_TO_ULONG(ulEflags));



			//// uty: test
			//{
			//	PVOID pCurrentRIP = NULL;
			//	ULONG ulTmp = 0;

			//	__asm int 3;
			//	DbgPrint("IRQL 0x%x\n", KeGetCurrentIrql());

			//	pCurrentRIP = (PVOID)VmxRead(GUEST_RIP);

			//	ulTmp = *(PUCHAR)pCurrentRIP;
			//}

			

		} 
		else if (movcrAccessType == 1) 
		{
			/* reg32 <-- CRx */

			if (movcrControlRegister == 0)
				x = GuestCR0;
			else if (movcrControlRegister == 3)
				x = GuestCR3;
			else
				x = GuestCR4;

			switch(movcrGeneralPurposeRegister) 
			{
			case 0:  GuestRegs->eax = x; break;
			case 1:  GuestRegs->ecx = x; break;
			case 2:  GuestRegs->edx = x; break;
			case 3:  GuestRegs->ebx = x; break;
			case 4:  GuestRegs->esp = x; break;
			case 5:  GuestRegs->ebp = x; break;
			case 6:  GuestRegs->esi = x; break;
			case 7:  GuestRegs->edi = x; break;
			default: break;
			}
		}
	}
}
//-----------------------------------------------------------------------------//
VOID doVmxExitHandler (PGUEST_REGS GuestRegs)
{
	ULONG ulExitReason = 0;


	ulExitReason = (ULONG)VmxRead(VM_EXIT_REASON);

	//__asm int 3;

	switch (ulExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, 
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD: 
	case EXIT_REASON_VMPTRST: 
	case EXIT_REASON_VMREAD:  
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
		{
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_EXCEPTION_NMI:
		{
			HandleNMI();
			//ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_CPUID:
		{
			HandleCPUID(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_INVD:
		{
			//_INVD();
			__asm wbinvd;
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_INVLPG:
		{
			HandleINVLPG();
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_VMCALL:
		{
			HandleVMCALL(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_CR_ACCESS:
		{
			//
			// The first processors to support the virtual-machine extensions 
			// supported only the 1-setting of this control.
			//

			HandleCR(GuestRegs);
			ResumeToNextInstruction();
			break;
		}

	case EXIT_REASON_EPT_VIOLATION:
		{
			//HandleEptViolation();
			break;
		}

	//case EXIT_REASON_TASK_SWITCH:
	//	{
	//		break;
	//	}

	default:
		{
			DbgPrint("VM_EXIT_REASION 0x%x\n", ulExitReason);
		}
		break;
	}
}
//-----------------------------------------------------------------------------//
ULONG g_ErrorCode = 0;
//-----------------------------------------------------------------------------//
__declspec(naked) VOID VmxExitHandler (VOID)
{
	__asm
	{
		//
		// Find out why it shows VMExit Reason 0x80000021
		// Bugs happened here. First vm exit is CR access, since there we have a bug,
		// it makes program write some garbage into registers in HandleCR()
		// So next time, vm will exit because of INVALID_GUEST_STATE
		//

			push edi
			push esi
			push ebp
			push esp
			push ebx
			push edx
			push ecx
			push eax

			push esp

			call	doVmxExitHandler

			pop eax
			pop ecx
			pop edx
			pop ebx
			pop esp
			pop ebp
			pop esi
			pop edi 

			//vmx_resume
			_emit 0xf
			_emit 0x1
			_emit 0xc3
	}

	g_ErrorCode = VmxRead(VM_INSTRUCTION_ERROR);
	DbgPrint("VM Instruction Error 0x%x\n", (ULONG)g_ErrorCode);
}
//-----------------------------------------------------------------------------//
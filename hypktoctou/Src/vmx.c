//  [5/4/2015 uty]
#include <ntddk.h>
#include "vmminitstate.h"
#include "msr.h"
#include "i386/msr-asm.h"
#include "i386/regs-asm.h"
#include "i386/vmx-asm.h"
#include "i386/common-asm.h"
#include "vmx.h"
#include "cpu.h"
#include "ept.h"
#include "shadowhook.h"
#include "common.h"
//-----------------------------------------------------------------------------//
ULONG
VmxAdjustControls (
	__in ULONG Ctl,
	__in ULONG Msr
	)
{
	MSR MsrValue = {0};

	MsrValue.Content = __readmsr (Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}
//-----------------------------------------------------------------------------//
NTSTATUS
EnableVMX (
	PVMM_INIT_STATE VMMInitState
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	IA32_VMX_BASIC_MSR IA32BasicMsr = {0};
	IA32_FEATURE_CONTROL_MSR IA32FeatureControlMsr = {0};

	CR4_REG Cr4 = {0};
	RFLAGS rFlags = {0};

	//
	// BUG! Should check VMXE in MSR first
	// set VMXE on a machine without vt will raise a #GP
	//

	RegSetCr4(RegGetCr4() | X86_CR4_VMXE);
	Cr4.Content = RegGetCr4();

	if (0 == Cr4.VMXE)
	{
		DbgPrint("EnableVMX(): VMX is not supported.\n");
		Status = STATUS_NOT_SUPPORTED;
		goto Exit0;
	}


	IA32BasicMsr.QuadPart = __readmsr(MSR_IA32_VMX_BASIC);
	IA32FeatureControlMsr.QuadPart = __readmsr(MSR_IA32_FEATURE_CONTROL);

	DbgPrint("VMXON Region Size 0x%x\n", IA32BasicMsr.szVmxOnRegion);
	DbgPrint("VMXON Access Width Bit 0x%x\n", IA32BasicMsr.PhyAddrWidth);
	DbgPrint("      [   1] --> 32-bit\n");
	DbgPrint("      [   0] --> 64-bit\n");
	DbgPrint("VMXON Memory Type 0x%x\n", IA32BasicMsr.MemType);
	DbgPrint("      [   0]  --> Strong Uncacheable\n");
	DbgPrint("      [ 1-5]  --> Unused\n");
	DbgPrint("      [   6]  --> Write Back\n");
	DbgPrint("      [7-15]  --> Unused\n");

	if (VMX_MEMTYPE_WRITEBACK != IA32BasicMsr.MemType)
	{
		DbgPrint("Unsupported memory type.\n");
		Status = STATUS_NOT_SUPPORTED;
		goto Exit0;
	}

	*(PULONG)(VMMInitState->VMXONRegion) = IA32BasicMsr.RevId;

	VmxTurnOn(VMMInitState->PhysicalVMXONRegion.HighPart, VMMInitState->PhysicalVMXONRegion.LowPart);

	rFlags.Content = RegGetEflags();
	if (1 == rFlags.CF)
	{
		DbgPrint("ERROR: VMXON operation failed.\n");
		Status = STATUS_UNSUCCESSFUL;
		goto Exit0;
	}

	DbgPrint("SUCCESS: VMXON operation completed.\n");
	DbgPrint("VMM is now running on processor %d.\n", KeGetCurrentProcessorNumber());

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
//BOOLEAN
//GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
//                     USHORT            Selector,
//                     PUCHAR            GdtBase)
//{
//    PSEGMENT_DESCRIPTOR SegDesc;
//
//    if (!SegmentSelector)
//        return FALSE;
//
//    if (Selector & 0x4)
//    {
//        return FALSE;
//    }
//
//    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));
//
//    SegmentSelector->SEL               = Selector;
//    SegmentSelector->BASE              = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
//    SegmentSelector->LIMIT             = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
//    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;
//
//    if (!(SegDesc->ATTR0 & 0x10))
//    { // LA_ACCESSED
//        ULONG64 Tmp;
//        // this is a TSS or callgate etc, save the base high part
//        Tmp                   = (*(PULONG64)((PUCHAR)SegDesc + 8));
//        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
//    }
//
//    if (SegmentSelector->ATTRIBUTES.Fields.G)
//    {
//        // 4096-bit granularity is enabled for this segment, scale the limit
//        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
//    }
//
//    return TRUE;
//}
////-----------------------------------------------------------------------------//
//VOID
//FillGuestSelectorData(
//    PVOID  GdtBase,
//    ULONG  Segreg,
//    USHORT Selector)
//{
//    SEGMENT_SELECTOR SegmentSelector = {0};
//    ULONG            AccessRights;
//
//    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
//    AccessRights = ((PUCHAR)&SegmentSelector.attributes)[0] + (((PUCHAR)&SegmentSelector.attributes)[1] << 12);
//
//    if (!Selector)
//        AccessRights |= 0x10000;
//
//    VmxWrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
//    VmxWrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
//    VmxWrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
//    VmxWrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
//}
//-----------------------------------------------------------------------------//
enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};
NTSTATUS
VmxSetupVMCS (
	PVMM_INIT_STATE VMMInitState,
	PVOID GuestRip,
	PVOID GuestRsp
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	IA32_VMX_BASIC_MSR IA32BasicMsr = {0};
	RFLAGS rFlags = {0};
	ULONG64 GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = {0};

	IA32BasicMsr.QuadPart = ReadMSRToLarge(MSR_IA32_VMX_BASIC);

	*(PULONG)VMMInitState->VMCSRegion = IA32BasicMsr.RevId;

	//VmxClear(VMMInitState->PhysicalVMCSRegion);
	VmxClear(VMMInitState->PhysicalVMCSRegion.HighPart, VMMInitState->PhysicalVMCSRegion.LowPart);
	rFlags.Content = RegGetEflags();
	if (0 != rFlags.CF || 0 != rFlags.ZF)
	{
		DbgPrint("ERROR: VMCLEAR operation failed.\n");
		goto Exit0;
	}

	//VmxPtrld(VMMInitState->PhysicalVMCSRegion);
	VmxPtrld(VMMInitState->PhysicalVMCSRegion.HighPart, VMMInitState->PhysicalVMCSRegion.LowPart);


	VmxWrite(HOST_ES_SELECTOR, RegGetEs() & 0xF8);
	VmxWrite(HOST_CS_SELECTOR, RegGetCs() & 0xF8);
	VmxWrite(HOST_SS_SELECTOR, RegGetSs() & 0xF8);
	VmxWrite(HOST_DS_SELECTOR, RegGetDs() & 0xF8);
	VmxWrite(HOST_FS_SELECTOR, RegGetFs() & 0xF8);
	VmxWrite(HOST_GS_SELECTOR, RegGetGs() & 0xF8);
	VmxWrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	VmxWrite(VMCS_LINK_POINTER, 0xFFFFFFFF);
	VmxWrite(VMCS_LINK_POINTER_HIGH, 0xFFFFFFFF);

	VmxWrite(GUEST_IA32_DEBUGCTL, ReadMSRToLarge(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	VmxWrite(GUEST_IA32_DEBUGCTL_HIGH, ReadMSRToLarge(MSR_IA32_DEBUGCTL) >> 32);


	/* Time-stamp counter offset */
	VmxWrite(TSC_OFFSET, 0);
	VmxWrite(TSC_OFFSET_HIGH, 0);

	VmxWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	VmxWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	VmxWrite(VM_EXIT_MSR_STORE_COUNT, 0);
	VmxWrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	VmxWrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	VmxWrite(VM_ENTRY_INTR_INFO_FIELD, 0);


	GdtBase = GetGdtBase();

	VmxFillGuestSelectorData ((PVOID)GdtBase, ES, RegGetEs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, CS, RegGetCs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, SS, RegGetSs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, DS, RegGetDs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, FS, RegGetFs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, GS, RegGetGs ());
	VmxFillGuestSelectorData ((PVOID)GdtBase, LDTR, GetLdtr());
	VmxFillGuestSelectorData ((PVOID)GdtBase, TR, GetTr());

	VmxWrite(GUEST_FS_BASE, ReadMSRToLarge(MSR_IA32_FS_BASE));
	VmxWrite(GUEST_GS_BASE, ReadMSRToLarge(MSR_IA32_GS_BASE));

	VmxWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	VmxWrite(GUEST_ACTIVITY_STATE, 0);   //Active state 


	// uty: test
	//VmxWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	//VmxWrite(SECONDARY_VM_EXEC_CONTROL, VmxAdjustControls(CPU_BASED_CTL2_RDTSCP, MSR_IA32_VMX_PROCBASED_CTLS2));

	DbgPrint("VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS) : 0x%x\n", VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS));
	VmxWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING | CPU_BASED_ACTIVATE_CTLS2, MSR_IA32_VMX_PROCBASED_CTLS));
	VmxWrite(SECONDARY_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS2));

	//VmxWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(/*CPU_BASED_INVLPG_EXITING*/CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING, MSR_IA32_VMX_PROCBASED_CTLS)); // uty: test


	VmxWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	VmxWrite(VM_EXIT_CONTROLS, VmxAdjustControls(/*VM_EXIT_IA32E_MODE |*/ VM_EXIT_ACK_INTRRUPT_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	VmxWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(/*VM_ENTRY_IA32E_MODE*/0, MSR_IA32_VMX_ENTRY_CTLS));

	VmxWrite(CR3_TARGET_COUNT,  0);
	VmxWrite(CR3_TARGET_VALUE0, 0);
	VmxWrite(CR3_TARGET_VALUE1, 0);                        
	VmxWrite(CR3_TARGET_VALUE2, 0);
	VmxWrite(CR3_TARGET_VALUE3, 0);

	VmxWrite(GUEST_CR0, RegGetCr0());
	VmxWrite(GUEST_CR3, RegGetCr3());
	VmxWrite(GUEST_CR4, RegGetCr4());

	VmxWrite(GUEST_DR7, 0x400);

	VmxWrite(HOST_CR0, RegGetCr0 ());
	VmxWrite(HOST_CR3, RegGetCr3 ());
	VmxWrite(HOST_CR4, RegGetCr4 ());

	
	VmxWrite(GUEST_GDTR_BASE, GetGdtBase());
	VmxWrite(GUEST_IDTR_BASE, GetIdtBase());
	VmxWrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	VmxWrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	VmxWrite(GUEST_RFLAGS, RegGetEflags ());

	VmxWrite(GUEST_SYSENTER_CS, ReadMSRToLarge (MSR_IA32_SYSENTER_CS));
	VmxWrite(GUEST_SYSENTER_EIP, ReadMSRToLarge (MSR_IA32_SYSENTER_EIP));
	VmxWrite(GUEST_SYSENTER_ESP, ReadMSRToLarge (MSR_IA32_SYSENTER_ESP));

	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
	VmxWrite (HOST_TR_BASE, SegmentSelector.base);

	VmxWrite(HOST_FS_BASE, ReadMSRToLarge (MSR_IA32_FS_BASE));
	VmxWrite(HOST_GS_BASE, ReadMSRToLarge (MSR_IA32_GS_BASE));

	VmxWrite(HOST_GDTR_BASE, GetGdtBase());
	VmxWrite(HOST_IDTR_BASE, GetIdtBase());
	
	VmxWrite(HOST_IA32_SYSENTER_CS, ReadMSRToLarge (MSR_IA32_SYSENTER_CS));
	VmxWrite(HOST_IA32_SYSENTER_EIP, ReadMSRToLarge (MSR_IA32_SYSENTER_EIP));
	VmxWrite(HOST_IA32_SYSENTER_ESP, ReadMSRToLarge (MSR_IA32_SYSENTER_ESP));


	VmxWrite(GUEST_RSP, (ULONG64) GuestRsp);     //setup guest sp
	VmxWrite(GUEST_RIP, (ULONG64) GuestRip);     //setup guest ip

	//
	// Set MSR bitmap, need all 0 to stop vmexit
	//

	VmxWrite(MSR_BITMAP, VMMInitState->PhysicalMsrBitmap.LowPart);
	VmxWrite(MSR_BITMAP_HIGH, VMMInitState->PhysicalMsrBitmap.HighPart);


	VmxWrite(HOST_RSP, ((ULONG64) VMMInitState->VMMStack + VMM_STACK_SIZE - 1));
	VmxWrite(HOST_RIP, (ULONG64) VmxExitHandler);


	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
//NTSTATUS
//VmxSetupVMCS_old (
//	PVMM_INIT_STATE VMMInitState,
//	PVOID GuestRip,
//	PVOID GuestRsp
//	)
//{
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//
//	IA32_VMX_BASIC_MSR IA32BasicMsr = {0};
//	RFLAGS eFlags = {0};
//	ULONG GdtBase = 0;
//	ULONG ulTemp = 0;
//
//
//	IA32BasicMsr.QuadPart = __readmsr(MSR_IA32_VMX_BASIC);
//
//	*(PULONG)VMMInitState->VMCSRegion = IA32BasicMsr.RevId;
//
//	VmxClear(VMMInitState->PhysicalVMCSRegion.HighPart, VMMInitState->PhysicalVMCSRegion.LowPart);
//	eFlags.Content = RegGetEflags();
//	if (0 != eFlags.CF || 0 != eFlags.ZF)
//	{
//		DbgPrint("ERROR: VMCLEAR operation failed.\n");
//		goto Exit0;
//	}
//
//	VmxPtrld(VMMInitState->PhysicalVMCSRegion.HighPart, VMMInitState->PhysicalVMCSRegion.LowPart);
//
//	/*16BIT Fields */
//
//	///*16BIT Host-Statel Fields. */
//	//VmxWrite(GUEST_ES_SELECTOR, RegGetEs());
//	//VmxWrite(GUEST_CS_SELECTOR, RegGetCs());
//	//VmxWrite(GUEST_SS_SELECTOR, RegGetSs());
//	//VmxWrite(GUEST_DS_SELECTOR, RegGetDs());
//	//VmxWrite(GUEST_FS_SELECTOR, RegGetFs());
//	//VmxWrite(GUEST_GS_SELECTOR, RegGetGs());
//	//VmxWrite(GUEST_LDTR_SELECTOR, GetLdtr());
//	//VmxWrite(GUEST_TR_SELECTOR, GetTr());
//	//
//	//DbgPrint("GUEST_ES_SELECTOR 0x%x\n", RegGetEs());
//	//DbgPrint("GUEST_CS_SELECTOR 0x%x\n", RegGetCs());
//	//DbgPrint("GUEST_SS_SELECTOR 0x%x\n", RegGetSs());
//	//DbgPrint("GUEST_DS_SELECTOR 0x%x\n", RegGetDs());
//	//DbgPrint("GUEST_FS_SELECTOR 0x%x\n", RegGetFs());
//	//DbgPrint("GUEST_GS_SELECTOR 0x%x\n", RegGetGs());
//	//DbgPrint("GUEST_LDTR_SELECTOR 0x%x\n", GetLdtr());
//	//DbgPrint("GUEST_TR_SELECTOR 0x%x\n", GetTr());  // TI flag?
//
//
//	/*16BIT Host-Statel Fields. */
//	VmxWrite(HOST_ES_SELECTOR, RegGetEs() & 0xFFF8);
//	VmxWrite(HOST_CS_SELECTOR, RegGetCs() & 0xFFF8);
//	VmxWrite(HOST_SS_SELECTOR, RegGetSs() & 0xFFF8);
//	VmxWrite(HOST_DS_SELECTOR, RegGetDs() & 0xFFF8);
//	VmxWrite(HOST_FS_SELECTOR, RegGetFs() & 0xFFF8);
//	VmxWrite(HOST_GS_SELECTOR, RegGetGs() & 0xFFF8);
//	VmxWrite(HOST_TR_SELECTOR, GetTr() & 0xFFF8);
//
//	DbgPrint("HOST_ES_SELECTOR 0x%x\n", RegGetEs() & 0xFFF8);
//	DbgPrint("HOST_CS_SELECTOR 0x%x\n", RegGetCs() & 0xFFF8);
//	DbgPrint("HOST_SS_SELECTOR 0x%x\n", RegGetSs() & 0xFFF8);
//	DbgPrint("HOST_DS_SELECTOR 0x%x\n", RegGetDs() & 0xFFF8);
//	DbgPrint("HOST_FS_SELECTOR 0x%x\n", RegGetFs() & 0xFFF8);
//	DbgPrint("HOST_GS_SELECTOR 0x%x\n", RegGetGs() & 0xFFF8);
//	DbgPrint("HOST_TR_SELECTOR 0x%x\n", GetTr() & 0xFFF8);
//
//	/* Exception bitmap */
// 
//  	//CmSetBit(&ulTemp, TRAP_DEBUG);
//	CmSetBit(&ulTemp, TRAP_INT3);
//  	VmxWrite(EXCEPTION_BITMAP, ulTemp);
//
//
//	//
//	// Set MSR bitmap, need all 0 to stop vmexit
//	//
//	VmxWrite(MSR_BITMAP, VMMInitState->PhysicalMsrBitmap.LowPart);
//	VmxWrite(MSR_BITMAP_HIGH, VMMInitState->PhysicalMsrBitmap.HighPart);
//
//
//	VmxWrite(VMCS_LINK_POINTER, 0xFFFFFFFF);
//	VmxWrite(VMCS_LINK_POINTER_HIGH, 0xFFFFFFFF);
//
//
//	VmxWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
//	VmxWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(/*CPU_BASED_INVLPG_EXITING*/0, MSR_IA32_VMX_PROCBASED_CTLS)); // uty: test
//
//	DbgPrint("CPU_BASED_VM_EXEC_CONTROL 0x%x\n", VmxAdjustControls(CPU_BASED_INVLPG_EXITING, MSR_IA32_VMX_PROCBASED_CTLS));
//	DbgPrint("PIN_BASED_VM_EXEC_CONTROL 0x%x\n", VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
//
//
//	/* Time-stamp counter offset */
// 	VmxWrite(TSC_OFFSET, 0);
// 	VmxWrite(TSC_OFFSET_HIGH, 0);
//
//
//	VmxWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
//	VmxWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
//
//
//	// 32 bit hypervisor cannot set VM_EXIT_IA32E_MODE
//	VmxWrite(VM_EXIT_CONTROLS, VmxAdjustControls(/*VM_EXIT_IA32E_MODE | */VM_EXIT_ACK_INTRRUPT_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
//	DbgPrint("VM_EXIT_CONTROLS 0x%x\n", VmxAdjustControls( VM_EXIT_ACK_INTRRUPT_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
//
//	VmxWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(/*VM_ENTRY_IA32E_MODE*/0, MSR_IA32_VMX_ENTRY_CTLS));
//
//	VmxWrite(VM_EXIT_MSR_STORE_COUNT, 0);
//	VmxWrite(VM_EXIT_MSR_LOAD_COUNT, 0);
//
//	VmxWrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
//	VmxWrite(VM_ENTRY_INTR_INFO_FIELD, 0);
//
//	// uty: test
//	GdtBase = GetGdtBase();
//
//	VmxFillGuestSelectorData ((PVOID)GdtBase, ES, RegGetEs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, CS, RegGetCs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, SS, RegGetSs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, DS, RegGetDs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, FS, RegGetFs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, GS, RegGetGs ());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, LDTR, GetLdtr());
//	VmxFillGuestSelectorData ((PVOID)GdtBase, TR, GetTr());
//
//
//	///*32BIT Guest-Statel Fields. */
//	//GdtBase = GetGdtBase();
//	//VmxWrite(GUEST_ES_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetEs()));
//	//VmxWrite(GUEST_CS_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetCs()));
//	//VmxWrite(GUEST_SS_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetSs()));
//	//VmxWrite(GUEST_DS_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetDs()));
//	//VmxWrite(GUEST_FS_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetFs()));
//	//VmxWrite(GUEST_GS_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetGs()));
//	//VmxWrite(GUEST_LDTR_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, GetLdtr()));
//	//VmxWrite(GUEST_TR_LIMIT, (ULONG)GetSegmentDescriptorLimit(GdtBase, GetTr()));
//
//	//DbgPrint("GUEST_ES_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetEs()));
//	//DbgPrint("GUEST_CS_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetCs()));
//	//DbgPrint("GUEST_SS_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetSs()));
//	//DbgPrint("GUEST_DS_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetDs()));
//	//DbgPrint("GUEST_FS_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetFs()));
//	//DbgPrint("GUEST_GS_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, RegGetGs()));
//	//DbgPrint("GUEST_LDTR_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, GetLdtr()));
//	//DbgPrint("GUEST_TR_LIMIT 0x%x\n", (ULONG)GetSegmentDescriptorLimit(GdtBase, GetTr()));
//
//	///* Guest GDTR/IDTR limit */
//	//VmxWrite(GUEST_GDTR_LIMIT, (ULONG)GetGdtLimit());
//	//VmxWrite(GUEST_IDTR_LIMIT, (ULONG)GetIdtLimit());
//
//	//DbgPrint("GUEST_GDTR_LIMIT 0x%x\n", (ULONG)GetGdtLimit());
//	//DbgPrint("GUEST_IDTR_LIMIT 0x%x\n", (ULONG)GetIdtLimit());
//
//	///* Set segment access rights */
//	//VmxWrite(GUEST_ES_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetEs()));
//	//VmxWrite(GUEST_CS_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetCs()));
//	//VmxWrite(GUEST_SS_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetSs()));
//	//VmxWrite(GUEST_DS_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetDs()));
//	//VmxWrite(GUEST_FS_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetFs()));
//	//VmxWrite(GUEST_GS_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetGs()));
//	//VmxWrite(GUEST_TR_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, GetTr()));
//	//VmxWrite(GUEST_LDTR_AR_BYTES, (ULONG)GetSegmentDescriptorAR(GdtBase, GetLdtr()));
//
//	//DbgPrint("GUEST_ES_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetEs()));
//	//DbgPrint("GUEST_CS_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetCs()));
//	//DbgPrint("GUEST_SS_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetSs()));
//	//DbgPrint("GUEST_DS_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetDs()));
//	//DbgPrint("GUEST_FS_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetFs()));
//	//DbgPrint("GUEST_GS_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, RegGetGs()));
//	//DbgPrint("GUEST_TR_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, GetTr()));
//	//DbgPrint("GUEST_LDTR_AR_BYTES 0x%x\n", (ULONG)GetSegmentDescriptorAR(GdtBase, GetLdtr()));
//
//
//	VmxWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
//	VmxWrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
//
//
//	VmxWrite(GUEST_CR0, RegGetCr0());
//	VmxWrite(GUEST_CR3, RegGetCr3());
//	VmxWrite(GUEST_CR4, RegGetCr4());
//
//	DbgPrint("GUEST_CR0 0x%x\n", RegGetCr0());
//	DbgPrint("GUEST_CR3 0x%x\n", RegGetCr3());
//	DbgPrint("GUEST_CR4 0x%x\n", RegGetCr4());
//	
//
//
//	//VmxWrite(GUEST_CS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetCs()));
//	//VmxWrite(GUEST_SS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetSs()));
//	//VmxWrite(GUEST_DS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetDs()));
//	//VmxWrite(GUEST_ES_BASE, GetSegmentDescriptorBase(GdtBase, RegGetEs()));
//	//VmxWrite(GUEST_FS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetFs()));
//	//VmxWrite(GUEST_GS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetGs()));
//	//VmxWrite(GUEST_LDTR_BASE, (ULONG)GetSegmentDescriptorBase(GdtBase, GetLdtr()));
//	//VmxWrite(GUEST_TR_BASE, (ULONG)GetSegmentDescriptorBase(GdtBase, GetTr()));
//	//VmxWrite(GUEST_GDTR_BASE, (ULONG)GetGdtBase());
//	//VmxWrite(GUEST_IDTR_BASE, (ULONG)GetIdtBase());
//
//	//DbgPrint("GUEST_CS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetCs()));
//	//DbgPrint("GUEST_SS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetSs()));
//	//DbgPrint("GUEST_DS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetDs()));
//	//DbgPrint("GUEST_ES_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetEs()));
//	//DbgPrint("GUEST_FS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetFs()));
//	//DbgPrint("GUEST_GS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetGs()));
//	//DbgPrint("GUEST_LDTR_BASE 0x%x\n", (ULONG)GetSegmentDescriptorBase(GdtBase, GetLdtr()));
//	//DbgPrint("GUEST_TR_BASE 0x%x\n", (ULONG)GetSegmentDescriptorBase(GdtBase, GetTr()));
//	//DbgPrint("GUEST_GDTR_BASE 0x%x\n", (ULONG)GetGdtBase());
//	//DbgPrint("GUEST_IDTR_BASE 0x%x\n", (ULONG)GetIdtBase());
//
//	VmxWrite(GUEST_DR7, 0x400);
//	VmxWrite(GUEST_RSP, (ULONG) GuestRsp);     //setup guest sp
//	VmxWrite(GUEST_RIP, (ULONG) GuestRip);     //setup guest ip
//
//	DbgPrint("GUEST_RSP 0x%x\n", GuestRsp);
//	DbgPrint("GUEST_RIP 0x%x\n", GuestRip);
//
//	VmxWrite(GUEST_RFLAGS, (ULONG)RegGetEflags ());
//	DbgPrint("GUEST_RFLAGS 0x%x\n", RegGetEflags ());
//
//
// 	VmxWrite(GUEST_SYSENTER_ESP, (ULONG)__readmsr (MSR_IA32_SYSENTER_ESP));
//	VmxWrite(GUEST_SYSENTER_EIP, (ULONG)__readmsr (MSR_IA32_SYSENTER_EIP));
//	VmxWrite(GUEST_SYSENTER_CS, (ULONG)__readmsr (MSR_IA32_SYSENTER_CS));
//
//	DbgPrint("GUEST_SYSENTER_ESP 0x%x\n", (ULONG)__readmsr (MSR_IA32_SYSENTER_ESP));
//	DbgPrint("GUEST_SYSENTER_EIP 0x%x\n", (ULONG)__readmsr (MSR_IA32_SYSENTER_EIP));
//	DbgPrint("GUEST_SYSENTER_CS 0x%x\n", (ULONG)__readmsr (MSR_IA32_SYSENTER_CS));
//
//
//	/* HOST State Fields. */
//	VmxWrite(HOST_CR0, RegGetCr0());
//	VmxWrite(HOST_CR3, RegGetCr3 ());
//	VmxWrite(HOST_CR4, RegGetCr4 ());
//
//	DbgPrint("HOST_CR0 0x%x\n", RegGetCr0());
//	DbgPrint("HOST_CR3 0x%x\n", RegGetCr3 ());
//	DbgPrint("HOST_CR4 0x%x\n", RegGetCr4 ());
//
//
//	/* Host FS, GS and TR base */
//	VmxWrite(HOST_FS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetFs()));
//	VmxWrite(HOST_GS_BASE, GetSegmentDescriptorBase(GdtBase, RegGetGs()));
//	VmxWrite(HOST_TR_BASE, (ULONG)GetSegmentDescriptorBase(GdtBase, GetTr()));
//
//
//	DbgPrint("HOST_FS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetFs()));
//	DbgPrint("HOST_GS_BASE 0x%x\n", GetSegmentDescriptorBase(GdtBase, RegGetGs()));
//	DbgPrint("HOST_TR_BASE 0x%x, selector 0x%x\n", GetSegmentDescriptorBase(GdtBase, GetTr()), GetTr());
//
//
//	VmxWrite(HOST_GDTR_BASE, (ULONG)GetGdtBase());
//	VmxWrite(HOST_IDTR_BASE, (ULONG)GetIdtBase());
//
//	DbgPrint("HOST_GDTR_BASE 0x%x\n", (ULONG)GetGdtBase());
//	DbgPrint("HOST_IDTR_BASE 0x%x\n", (ULONG)GetIdtBase());
//
//	VmxWrite(HOST_IA32_SYSENTER_CS, (ULONG)__readmsr (MSR_IA32_SYSENTER_CS));
//	VmxWrite(HOST_IA32_SYSENTER_ESP, (ULONG)__readmsr (MSR_IA32_SYSENTER_ESP));
//	VmxWrite(HOST_IA32_SYSENTER_EIP, (ULONG)__readmsr (MSR_IA32_SYSENTER_EIP));
//
//	RtlZeroMemory((PULONG)(VMMInitState->VMCSRegion) + 4, 4);
//
//	VmxWrite(HOST_RSP, ((ULONG) VMMInitState->VMMStack + VMM_STACK_SIZE - 1));
//	VmxWrite(HOST_RIP, (ULONG) VmxExitHandler);
//
//
//	Status = STATUS_SUCCESS;
//Exit0:
//	return Status;
//}
//-----------------------------------------------------------------------------//
NTSTATUS
doStartVMX (
	PVOID GuestRsp
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PVMM_INIT_STATE pCurrentVMMInitState = NULL;

	ULONG64 ErrorCode = 0;

	
	DbgPrint("In DoStartVMX, Processor %d\n", KeGetCurrentProcessorNumber());

	pCurrentVMMInitState = &g_VMMInitState[KeGetCurrentProcessorNumber()];

	Status = EnableVMX(pCurrentVMMInitState);
	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("EnableVMX failed.\n");
		goto Exit0;
	}

	//
	// minimal vmcs settings
	//

	Status = VmxSetupVMCS(pCurrentVMMInitState, StartVMXBack, GuestRsp);
	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("VmxSetupVMCS failed.\n");
		goto Exit0;
	}

	//
	//  extra vmcs settings goes here
	//

	//Status = EptInit();
	//if (STATUS_SUCCESS != Status)
	//{
	//	DbgPrint("EptInit failed 0x%x\n", Status);
	//	goto Exit0;
	//}

// 	Status = ShadowHookInit();
// 	if (STATUS_SUCCESS != Status)
// 	{
// 		DbgPrint("ShadowHookInit failed 0x%x\n", Status);
// 		goto Exit0;
// 	}


	VmxLaunch();

	// if VmxLaunch success, never here.

	ErrorCode = VmxRead(VM_INSTRUCTION_ERROR);
	DbgPrint("VM Instruction Error 0x%x\n", (ULONG)ErrorCode);

	Status = STATUS_SUCCESS;
Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
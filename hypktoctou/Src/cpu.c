//  [5/5/2015 uty]
#include <ntddk.h>
#include "cpu.h"
////-----------------------------------------------------------------------------//
//NTSTATUS
//InitializeSegmentSelector (
//	PSEGMENT_SELECTOR SegmentSelector, 
//	USHORT Selector,
//	ULONG64 GdtBase
//	)
//{
//	PSEGMENT_DESCRIPTOR2 SegDesc;
//
//	if (!SegmentSelector)
//		return STATUS_INVALID_PARAMETER;
//
//	if (Selector & 0x4) {
//		DbgPrint("InitializeSegmentSelector(): Given selector points to LDT\n", Selector);
//		return STATUS_INVALID_PARAMETER;
//	}
//
//	SegDesc = (PSEGMENT_DESCRIPTOR2) ((PUCHAR) GdtBase + (Selector & ~0x7));
//
//	SegmentSelector->sel = Selector;
//	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
//	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
//	//SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;
//	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 8;
//
//	if (!(SegDesc->attr0 & LA_STANDARD)) {
//		ULONG64 tmp;
//		// this is a TSS or callgate etc, save the base high part
//		tmp = (*(PULONG64) ((PUCHAR) SegDesc + 8));
//		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
//	}
//
//	if (SegmentSelector->attributes.fields.g) {
//		// 4096-bit granularity is enabled for this segment, scale the limit
//		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
//	}
//
//	return STATUS_SUCCESS;
//}
////-----------------------------------------------------------------------------//
//ULONG64
//GetSegmentDescriptorBase (
//	ULONG64 gdt_base,
//	USHORT seg_selector
//	)
//{
//// 	ULONG base = 0;
//// 	SEGMENT_DESCRIPTOR	segDescriptor = {0};
//// 
//// 	RtlCopyBytes( &segDescriptor, (PVOID)(gdt_base + (seg_selector >> 3) * 8), 8 );
//// 	base = segDescriptor.BaseHi;
//// 	base <<= 8;
//// 	base |= segDescriptor.BaseMid;
//// 	base <<= 16;
//// 	base |= segDescriptor.BaseLo;
//	SEGMENT_SELECTOR SegmentSelector = { 0 };
//
//	InitializeSegmentSelector(&SegmentSelector, seg_selector, gdt_base);
//
//	return SegmentSelector.base;
//
//}
////-----------------------------------------------------------------------------//
//// ULONG
//// GetSegmentDescriptorDPL (
//// 	ULONG gdt_base,
//// 	USHORT seg_selector
//// 	)
//// {
//// 	SEGMENT_DESCRIPTOR segDescriptor = {0};
//// 
//// 	RtlCopyBytes(&segDescriptor, (PVOID)(gdt_base + (seg_selector >> 3) * 8), 8);
//// 
//// 	return segDescriptor.DPL;
//// }
////-----------------------------------------------------------------------------//
//ULONG
//GetSegmentDescriptorLimit (
//	ULONG64 gdt_base,
//	USHORT selector
//	)
//{
//	SEGMENT_SELECTOR SegmentSelector = { 0 };
//
//	InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);
//
//	return SegmentSelector.limit;
//}
////-----------------------------------------------------------------------------//
//ULONG
//GetSegmentDescriptorAR (
//	ULONG64 gdt_base,
//	USHORT selector
//	)
//{
//	SEGMENT_SELECTOR SegmentSelector = { 0 };
//	ULONG uAccessRights;
//
//	InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);
//
//	//uAccessRights = ((PUCHAR) & SegmentSelector.attributes)[0] + (((PUCHAR) & SegmentSelector.attributes)[1] << 12);
//	uAccessRights = (ULONG)SegmentSelector.attributes.UCHARs;
//
//	if (!selector)
//		uAccessRights |= 0x10000;
//
//	return uAccessRights;
//}
//-----------------------------------------------------------------------------//

////////////////////////////////////
//  SEGMENT DESCRIPTOR OPERATORS  //
////////////////////////////////////

static NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, 
					  USHORT Selector, ULONG GdtBase)
{
  PSEGMENT_DESCRIPTOR2 SegDesc;

  if (!SegmentSelector)
    return STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    //Log("InitializeSegmentSelector(): Given selector points to LDT\n", Selector);
    return STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR2) ((PUCHAR) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel = Selector;
  SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
  SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
  //SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;
  SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 8;

  if (!(SegDesc->attr0 & LA_STANDARD)) {
    ULONG64 tmp;
    // this is a TSS or callgate etc, save the base high part
    tmp = (*(PULONG64) ((PUCHAR) SegDesc + 8));
    SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
  }

  if (SegmentSelector->attributes.fields.g) {
    // 4096-bit granularity is enabled for this segment, scale the limit
    SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
  }

  return STATUS_SUCCESS;
}

ULONG GetSegmentDescriptorBase(ULONG gdt_base, USHORT seg_selector)
{
  ULONG			base = 0;
  SEGMENT_DESCRIPTOR	segDescriptor = {0};
	
  RtlCopyBytes( &segDescriptor, (ULONG *)(gdt_base + (seg_selector >> 3) * 8), 8 );
  base = segDescriptor.BaseHi;
  base <<= 8;
  base |= segDescriptor.BaseMid;
  base <<= 16;
  base |= segDescriptor.BaseLo;

  return base;
}

ULONG GetSegmentDescriptorDPL(ULONG gdt_base, USHORT seg_selector)
{
  SEGMENT_DESCRIPTOR segDescriptor = {0};
	
  RtlCopyBytes(&segDescriptor, (ULONG *)(gdt_base + (seg_selector >> 3) * 8), 8);
	
  return segDescriptor.DPL;
}

ULONG GetSegmentDescriptorLimit(ULONG gdt_base, USHORT selector)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };

  InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);
	
  return SegmentSelector.limit;
}

ULONG GetSegmentDescriptorAR(ULONG gdt_base, USHORT selector)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };
  ULONG uAccessRights;

  InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);

  //uAccessRights = ((PUCHAR) & SegmentSelector.attributes)[0] + (((PUCHAR) & SegmentSelector.attributes)[1] << 12);
  uAccessRights = (ULONG)SegmentSelector.attributes.UCHARs;
	
  if (!selector)
    uAccessRights |= 0x10000;

  return uAccessRights;
}

///* This one is Windows (XP?)-dependent, because it must also take into account the
//   possibility that we are virtualized (see the redpill) */
//ULONG32 RegGetIdtBase()
//{
//  IDTR tmp_idt;
//  ULONG inmem_base, idtr_base;
//
//  /* Read IDTR */
//  __asm { SIDT tmp_idt };
//  idtr_base = (tmp_idt.BaseHi << 16 | tmp_idt.BaseLo);
//
//  /* Get IDT base from memory */
//  inmem_base = *(ULONG*) WINDOWS_PIDT_BASE;
//
//  if (idtr_base != inmem_base) {
//    /* Virtualized! */
//  }
//
//  return inmem_base;
//}
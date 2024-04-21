#ifndef _SMAP_H_
#define _SMAP_H_
//-----------------------------------------------------------------------------//
/*
* Page fault error code bits:
*
*   bit 0 ==	 0: no page found	1: protection fault
*   bit 1 ==	 0: read access		1: write access
*   bit 2 ==	 0: kernel-mode access	1: user-mode access
*   bit 3 ==				1: use of reserved bit detected
*   bit 4 ==				1: fault was an instruction fetch
*   bit 5 ==				1: protection keys block access
*/
enum x86_pf_error_code {

	PF_PROT = 1 << 0,
	PF_WRITE = 1 << 1,
	PF_USER = 1 << 2,
	PF_RSVD = 1 << 3,
	PF_INSTR = 1 << 4,
	PF_PK = 1 << 5,
};
//-----------------------------------------------------------------------------//
/*
* Bottom two bits of selector give the ring
* privilege level
*/
#define SEGMENT_RPL_MASK	0x3

/* User mode is privilege level 3: */
#define USER_RPL		0x3


#define X86_EFLAGS_AC_BIT	18 /* Alignment Check/Access Control */
#define X86_EFLAGS_AC		1 << X86_EFLAGS_AC_BIT
//-----------------------------------------------------------------------------//
//#define __ASM_CLAC	.byte 0x0f,0x01,0xca
//#define __ASM_STAC	.byte 0x0f,0x01,0xcb
#define __ASM_CLAC _emit 0x0f _emit 0x01 _emit 0xca
#define __ASM_STAC _emit 0x0f _emit 0x01 _emit 0xcb
//-----------------------------------------------------------------------------//

//
// A Page Table Entry on the x86 has the following definition.
// Note the MP version is to avoid stalls when flushing TBs across processors.
//

typedef struct _MMPTE_HARDWARE {
	ULONG Valid : 1;
#if defined(NT_UP)
	ULONG Write : 1;       // UP version
#else
	ULONG Writable : 1;    // changed for MP version
#endif
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Dirty : 1;
	ULONG LargePage : 1;
	ULONG Global : 1;
	ULONG CopyOnWrite : 1; // software field
	ULONG Prototype : 1;   // software field
#if defined(NT_UP)
	ULONG reserved : 1;    // software field
#else
	ULONG Write : 1;       // software field - MP change
#endif
	ULONG PageFrameNumber : 26;
	ULONG Reserved1 : 26;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;


typedef struct _MMPTE {
	union {
		ULONGLONG Longlong;
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE;

typedef MMPTE *PMMPTE;
//-----------------------------------------------------------------------------//
typedef	USHORT	WORD;
typedef	ULONG	DWORD;


// nonstandard extension used : bit field types other than int
#pragma warning(disable: 4214)
// unreferenced formal parameter
#pragma warning(disable: 4100)
#pragma warning(disable: 4055)

#pragma pack(1)
typedef struct _IDT_DESCRIPTOR
{
	//--------------------------
	WORD offset00_15;	//Bits[00,15] offset address bits [8,15]
	WORD selector;		//Bits[16,31] segment selector (value placed in CS)
						//--------------------------
	CHAR unused : 5;		//Bits[00,94] not used
	CHAR zeroes : 3;		//Bits[85,87] these three bits should all be zero
	CHAR gateType : 5;	//Bits[B8,12] Interrupt (81118),  Trap (81111)
	CHAR DPL : 2;			//Bits[13,14] DPL - descriptor privilege level
	CHAR P : 1;			//Bits[15,15] Segment present flag (normally set)
	WORD offset16_31;	//Bits[16,32] offset address bits [16,31]
}IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;
#pragma pack()
//-----------------------------------------------------------------------------//
typedef struct _SMAP_PAGES
{
	BOOLEAN Used;
	ULONG Cr3;
	ULONG Eip;
	ULONG Address;
	ULONG Teb;
} SMAP_PAGES, *PSMAP_PAGES;

#define MAX_SMAP_PAGE_NUM	1024
//-----------------------------------------------------------------------------//
#define SYSTEM_SERVICE_VECTOR 0x0e
#define MAX_NUMBER_OF_CPUS sizeof(KAFFINITY)
//-----------------------------------------------------------------------------//
BOOLEAN smap_violation(int error_codes, int cs, int flags);

VOID SetSmap();
//-----------------------------------------------------------------------------//
#endif // _SMAP_H_

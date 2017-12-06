/*
 * cpuid2json.c
 * Copyright (C) 2015-2017 CYRIL INGENIERIE
 * Licenses: GPL2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VENDOR_INTEL	"GenuineIntel"
#define VENDOR_AMD	"AuthenticAMD"

#define PAGE_SIZE 4096

typedef struct	// Basic CPUID Function.
{
		unsigned int LargestStdFunc, LargestExtFunc, EBX, ECX, EDX;
} CPUID_0x00000000;

typedef struct
{
	struct
	{
		unsigned char Chr[4];
	} AX, BX, CX, DX;
} BRAND;

typedef struct
{
	union
	{
	    struct SIGNATURE
	    {
		unsigned int
		Stepping	:  4-0,
		Model		:  8-4,
		Family		: 12-8,
		ProcType	: 14-12,
		Unused1		: 16-14,
		ExtModel	: 20-16,
		ExtFamily	: 28-20,
		Unused2		: 32-28;
	    } EAX;
		unsigned int Signature;
	};
	struct
	{
		unsigned int
		Brand_ID	:  8-0,
		CLFSH_Size	: 16-8,
		MaxThread	: 24-16,
		Apic_ID		: 32-24;
	} EBX;
	struct
	{
		unsigned int
		SSE3	:  1-0,  // AMD Family 0Fh
		PCLMULDQ:  2-1,
		DTES64	:  3-2,
		MONITOR	:  4-3,
		DS_CPL	:  5-4,
		VMX	:  6-5,
		SMX	:  7-6,
		EIST	:  8-7,
		TM2	:  9-8,
		SSSE3	: 10-9,  // AMD Family 0Fh
		CNXT_ID	: 11-10,
		Unused1	: 12-11,
		FMA	: 13-12,
		CMPXCH16: 14-13,
		xTPR	: 15-14,
		PDCM	: 16-15,
		Unused2	: 17-16,
		PCID	: 18-17,
		DCA	: 19-18,
		SSE41	: 20-19,
		SSE42	: 21-20,
		x2APIC	: 22-21,
		MOVBE	: 23-22,
		POPCNT	: 24-23,
		TSCDEAD	: 25-24,
		AES	: 26-25,
		XSAVE	: 27-26,
		OSXSAVE	: 28-27,
		AVX	: 29-28,
		F16C	: 30-29,
		RDRAND	: 31-30,
		Hyperv	: 32-31;
	} ECX;
	struct
	{	// Most common x86
		unsigned int
		FPU	:  1-0,
		VME	:  2-1,
		DE	:  3-2,
		PSE	:  4-3,
		TSC	:  5-4,
		MSR	:  6-5,
		PAE	:  7-6,
		MCE	:  8-7,
		CMPXCH8	:  9-8,
		APIC	: 10-9,
		Unused1	: 11-10,
		SEP	: 12-11,
		MTRR	: 13-12,
		PGE	: 14-13,
		MCA	: 15-14,
		CMOV	: 16-15,
		PAT	: 17-16,
		PSE36	: 18-17,
		PSN	: 19-18, // Intel
		CLFSH	: 20-19,
		Unused2	: 21-20,
		DS_PEBS	: 22-21,
		ACPI	: 23-22,
		MMX	: 24-23,
		FXSR	: 25-24, // FXSAVE and FXRSTOR instructions.
		SSE	: 26-25,
		SSE2	: 27-26,
		SS	: 28-27, // Intel
		HTT	: 29-28,
		TM1	: 30-29, // Intel
		Unused3	: 31-30,
		PBE	: 32-31; // Intel
	} EDX;
} CPUID_0x00000001;

typedef struct	// MONITOR & MWAIT Leaf.
{		// Common x86
	struct
	{
		unsigned int
		SmallestSize	: 16-0,
		ReservedBits	: 32-16;
	} EAX;
	struct
	{
		unsigned int
		LargestSize	: 16-0,
		ReservedBits	: 32-16;
	} EBX;
	struct
	{
		unsigned int
		EMX_MWAIT	:  1-0,
		IBE_MWAIT	:  2-1,
		ReservedBits	: 32-2;
	} ECX;
	struct
	{	// Intel reseved.
		unsigned int
		Num_C0_MWAIT	:  4-0,
		Num_C1_MWAIT	:  8-4,
		Num_C2_MWAIT	: 12-8,
		Num_C3_MWAIT	: 16-12,
		Num_C4_MWAIT	: 20-16,
		ReservedBits	: 32-20;
	} EDX;
}  CPUID_0x00000005;

typedef struct THERMAL_POWER_LEAF
{	// Thermal and Power Management Leaf.
	struct
	{	// Most Intel reserved.
		unsigned int
		DTS	:  1-0,
		TurboIDA:  2-1, // Reports bit 38 of MSR 0x1a0
		ARAT	:  3-2, // Common x86
		Unused1	:  4-3,
		PLN	:  5-4,
		ECMD	:  6-5,
		PTM	:  7-6,
		HWP_Reg	:  8-7, // Hardware Performance registers
		HWP_Int	:  9-8, // IA32_HWP_INTERRUPT HWP_Notification.
		HWP_Act	: 10-9, // IA32_HWP_REQUEST Activity_Window
		HWP_Prf	: 11-10,// IA32_HWP_REQUEST Performance_Pref.
		HWP_Lvl	: 12-11,// IA32_HWP_REQUEST_PKG
		Unused2	: 13-12,
		HDC_Reg	: 15-13,// Hardware Duty Cycling registers
		Unused3	: 32-15;
	} EAX;
	struct
	{	// Intel reserved.
		unsigned int
		Threshld:  4-0,
		Unused1	: 32-4;
	} EBX;
    union
    {
	struct
	{	// Intel reserved.
		unsigned int
		HCF_Cap	:  1-0, // MSR: IA32_MPERF (E7H) & IA32_APERF (E8H)
		ACNT_Cap:  2-1,
		Unused1	:  3-2,
		SETBH	:  4-3,
		Unused2	: 32-4;
	};
	struct
	{	// AMD reserved.
		unsigned int
		EffFreq	:  1-0, // MSR0000_00E7 (MPERF) & MSR0000_00E8 (APERF)
		NotUsed : 32-1;
	};
    } ECX;
	struct
	{	// Intel reserved.
		unsigned int
		Unused1	: 32-0;
	} EDX;
} CPUID_0x00000006;

typedef struct	// Extended Feature Flags Enumeration Leaf.
{
	struct
	{	// Common x86
		unsigned int
		MaxSubLeaf	: 32-0;
	} EAX;
	struct
	{
		unsigned int
		FSGSBASE	:  1-0, // Common x86
		TSC_ADJUST	:  2-1,
		Unused1		:  3-2,
		BMI1		:  4-3, // Common x86
		HLE		:  5-4,
		AVX2		:  6-5, // Common x86
		Unused2		:  7-6,
		SMEP		:  8-7, // Common x86
		BMI2		:  9-8, // Common x86
		FastStrings	: 10-9,
		INVPCID		: 11-10,
		RTM		: 12-11,
		PQM		: 13-12,
		FPU_CS_DS	: 14-13,
		MPX		: 15-14,
		PQE		: 16-15,
		Unused3		: 18-16,
		RDSEED		: 19-18,
		ADX		: 20-19,
		SMAP		: 21-20,
		Unused4		: 25-21,
		ProcessorTrace	: 26-25,
		Unused5		: 32-26;
	} EBX;
	struct
	{	// Intel reserved.
		unsigned int
		PREFETCHWT1	:  1-0,
		Unused1		:  3-1,
		PKU		:  4-3,
		OSPKE		:  5-4,
		Unused2		: 32-5;
	} ECX;
		unsigned int
	EDX			: 32-0; // Intel reserved.
} CPUID_0x00000007;

typedef struct	// Architectural Performance Monitoring Leaf.
{	// Intel reserved.
	struct
	{
		unsigned int
		Version	:  8-0,
		MonCtrs	: 16-8,
		MonWidth: 24-16,
		VectorSz: 32-24;
	} EAX;
	struct
	{
		unsigned int
		CoreCycles	:  1-0,
		InstrRetired	:  2-1,
		RefCycles	:  3-2,
		LLC_Ref		:  4-3,
		LLC_Misses	:  5-4,
		BranchRetired	:  6-5,
		BranchMispred	:  7-6,
		ReservedBits	: 32-7;
	} EBX;
	struct
	{
		unsigned int
		Unused1	: 32-0;
	} ECX;
	struct
	{
		unsigned int
		FixCtrs	:  5-0,
		FixWidth: 13-5,
		Unused1	: 32-13;
	} EDX;
} CPUID_0x0000000a;

typedef	struct
{
    union
    {
	struct	{ // Intel reserved.
		unsigned int
		LAHFSAHF:  1-0,  // LAHF and SAHF instruction support.
		Unused1	: 32-1;
	};
	struct	{ // AMD reserved.
		unsigned int
		// Family 0Fh :
		LahfSahf:  1-0,
		MP_Mode	:  2-1,  // Core multi-processing legacy mode.
		SVM	:  3-2,  // Secure virtual machine.
		Ext_APIC:  4-3,  // Extended APIC space.
		AltMov	:  5-4,	 // AltMovCr8
		ABM	:  6-5,  // LZCNT instruction support.
		SSE4A	:  7-6,
		AlignSSE:  8-7,  // Misaligned SSE mode.
		PREFETCH:  9-8,  // 3DNow PREFETCH, PREFETCHW instruction.
		// Family 15h :
		OSVW	: 10-9,  // OS-visible workaround support.
		IBS	: 11-10, // Instruction based sampling.
		XOP	: 12-11, // Extended operation support.
		SKINIT	: 13-12, // SKINIT and STGI support.
		WDT	: 14-13, // Watchdog timer support.
		NotUsed1: 15-14,
		LWP	: 16-15, // Lightweight profiling support.
		FMA4	: 17-16, // Four-operand FMA instruction.
		TCE	: 18-17, // Translation Cache Extension.
		NotUsed2: 21-18,
		TBM	: 22-21, // Trailing bit manipulation.
		TopoExt	: 23-22, // Topology extensions support.
		PerfCore: 24-23, // PerfCtrExtCore MSR.
		PerfNB	: 25-24, // PerfCtrExtNB MSR.
		NotUsed3: 26-25,
		Data_BP	: 27-26, // Data access breakpoint extension.
		PerfTSC	: 28-27, // Performance TSC MSR.
		PerfL2I	: 29-28, // L2I performance counter extensions support.
		MWaitExt: 30-29, // MWAITX/MONITORX support.
		NotUsed4: 32-30;
	};
    } ECX;
    union
    {
	struct { // Intel reserved.
		unsigned int
		Unused1	: 11-0,
		SYSCALL	: 12-11,
		Unused2	: 20-12,
		XD_Bit	: 21-20,
		Unused3	: 26-21,
		PG_1GB	: 27-26,
		RdTSCP	: 28-27,
		Unused4	: 29-28,
		IA64	: 30-29,
		Unused5	: 32-30;
	};
	struct { // AMD reserved.
		unsigned int	 // Most bits equal to CPUID 0x01
		FPU	:  1-0,
		VME	:  2-1,  // Virtual-mode enhancements.
		DE	:  3-2,  // Debugging extensions.
		PSE	:  4-3,  // Page-size extensions.
		TSC	:  5-4,
		MSR	:  6-5,  // AMD MSR.
		PAE	:  7-6,
		MCE	:  8-7,
		CMPXCH8	:  9-8,
		APIC	: 10-9,
		NotUsed1: 11-10,
		SEP	: 12-11,
		MTRR	: 13-12,
		PGE	: 14-13,
		MCA	: 15-14,
		CMOV	: 16-15,
		PAT	: 17-16,
		PSE36	: 18-17,
		NotUsed2: 20-18,
		NX	: 21-20, // No-execute page protection.
		NotUsed3: 22-21,
		MMX_Ext : 23-22, // MMX extensions.
		MMX	: 24-23,
		FXSR	: 25-24,
		FFXSR	: 26-25, // FXSAVE and FXRSTOR optimizations.
		Page1GB	: 27-26,
		RDTSCP	: 28-27,
		NotUsed4: 29-28,
		LM	: 30-29, // Long mode.
		_3DNowEx: 31-30, // Extensions to 3DNow!
		_3DNow	: 32-31; // 3DNow! instructions.
	};
    } EDX;
} CPUID_0x80000001;

typedef struct	// Architectural Performance Monitoring Leaf.
{
	struct
	{
		unsigned int
		Unused1	: 32-0;
	} EAX, EBX, ECX;
    union
    {
	struct { // Intel reserved.
		unsigned int
		Unused1	:  8-0,
		Inv_TSC	:  9-8, // Invariant TSC available if 1
		Unused2	: 32-9;
	};
      union
      {		// AMD Family 0Fh
	struct {
		unsigned int
		TS	:  1-0,  // Temperature sensor
		FID	:  2-1,  // Frequency ID control is supported.
		VID	:  3-2,  // Voltage ID control is supported.
		TTP	:  4-3,  // THERMTRIP is supported = 1.
		TM	:  5-4,  // Hardware thermal control (HTC).
		STC	:  6-5,  // K7-K8: Software thermal control (STC)
		_100MHz	:  7-6,  // 100 MHz multiplier Control.
		NotUsed	: 32-7;
	};
	struct { // AMD Family 15h
		unsigned int
		Fam_0Fh	:  7-0,  // Family 0Fh features.
		HwPstate:  8-7,  // Hardware P-state control msr exist ?
		TscInv	:  9-8,  // Invariant TSC ?
		CPB	: 10-9,  // Core performance boost.
		EffFrqRO: 11-10, // Read-only effective frequency interf. msr ?
		ProcFb	: 12-11, // Processor feedback interface available if 1
		ProcPwr	: 13-12, // Core power reporting interface supported.
		Reserved: 32-13;
	};
      };
    } EDX;
} CPUID_0x80000007;

typedef struct	// BSP CPUID features.
{
	CPUID_0x00000000 Basic;
	CPUID_0x00000001 Std;
	CPUID_0x00000005 MWait;
	CPUID_0x00000006 Power;
	CPUID_0x00000007 ExtFeature;
	CPUID_0x0000000a PerfMon;
	CPUID_0x80000001 ExtInfo;
	CPUID_0x80000007 AdvPower;

	unsigned int	FactoryFreq;
	char		VendorID[12 + 2],
			Brand[48 + 2];	// 64 bits padding
} FEATURES;

typedef struct
{
	FEATURES	Features;
	unsigned int	CPU_Count;
} PROC;

void AMD_Core_Count(unsigned int *pCount)
{
	unsigned int eax = 0x0, ebx = 0x0, ecx = 0x0, edx = 0x0;

	asm volatile
	(
		"mov	$0x80000008, %%eax"	"\n\t"
		"xor	%%ebx, %%ebx"		"\n\t"
		"xor	%%ecx, %%ecx"		"\n\t"
		"xor	%%edx, %%edx"		"\n\t"
		"cpuid"				"\n\t"
		"mov	%%eax, %0"		"\n\t"
		"mov	%%ebx, %1"		"\n\t"
		"mov	%%ecx, %2"		"\n\t"
		"mov	%%edx, %3"
		: "=r" (eax),
		  "=r" (ebx),
		  "=r" (ecx),
		  "=r" (edx)
		:
		: "%eax", "%ebx", "%ecx", "%edx"
	);
	*pCount = 1 + (ecx & 0xf);
}

void Intel_Core_Count(unsigned int *pCount)
{
	unsigned int eax = 0x0, ebx = 0x0, ecx = 0x0, edx = 0x0;

	asm volatile
	(
		"mov	$0x4,  %%eax"	"\n\t"
		"xor	%%ebx, %%ebx"	"\n\t"
		"xor	%%ecx, %%ecx"	"\n\t"
		"xor	%%edx, %%edx"	"\n\t"
		"cpuid"			"\n\t"
		"mov	%%eax, %0"	"\n\t"
		"mov	%%ebx, %1"	"\n\t"
		"mov	%%ecx, %2"	"\n\t"
		"mov	%%edx, %3"
		: "=r" (eax),
		  "=r" (ebx),
		  "=r" (ecx),
		  "=r" (edx)
		:
		: "%eax", "%ebx", "%ecx", "%edx"
	);
	*pCount = 1 + ((eax >> 26) & 0x3f);
}

void Proc_Brand(char *pBrand)
{
	char tmpString[48 + 1] = {0x20};
	unsigned int ix = 0, jx = 0, px = 0;
	BRAND Brand;

	for (ix = 0; ix < 3; ix++)
	{
		asm volatile
		(
			"cpuid"
			: "=a"  (Brand.AX),
			  "=b"  (Brand.BX),
			  "=c"  (Brand.CX),
			  "=d"  (Brand.DX)
			: "a"   (0x80000002 + ix)
		);
		for (jx = 0; jx < 4; jx++, px++) {
			tmpString[px     ] = Brand.AX.Chr[jx];
			tmpString[px +  4] = Brand.BX.Chr[jx];
			tmpString[px +  8] = Brand.CX.Chr[jx];
			tmpString[px + 12] = Brand.DX.Chr[jx];
		}
		px += 12;
	}
	for (ix = jx = 0; jx < px; jx++)
		if (!(tmpString[jx] == 0x20 && tmpString[jx+1] == 0x20))
			pBrand[ix++] = tmpString[jx];
}

// Retreive the Processor features through calls to the CPUID instruction.
void Proc_Features(FEATURES *Features)
{
	asm volatile
	(
		"cpuid"
		: "=a"	(Features->Basic.LargestStdFunc),
		  "=b"	(Features->Basic.EBX),
		  "=c"	(Features->Basic.ECX),
		  "=d"	(Features->Basic.EDX)
		: "a" (0x0)
	);
	Features->VendorID[ 0] =  Features->Basic.EBX;
	Features->VendorID[ 1] = (Features->Basic.EBX >> 8);
	Features->VendorID[ 2] = (Features->Basic.EBX >> 16);
	Features->VendorID[ 3] = (Features->Basic.EBX >> 24);
	Features->VendorID[ 4] =  Features->Basic.EDX;
	Features->VendorID[ 5] = (Features->Basic.EDX >> 8);
	Features->VendorID[ 6] = (Features->Basic.EDX >> 16);
	Features->VendorID[ 7] = (Features->Basic.EDX >> 24);
	Features->VendorID[ 8] =  Features->Basic.ECX;
	Features->VendorID[ 9] = (Features->Basic.ECX >> 8);
	Features->VendorID[10] = (Features->Basic.ECX >> 16);
	Features->VendorID[11] = (Features->Basic.ECX >> 24);

	asm volatile
	(
		"cpuid"
		: "=a"	(Features->Std.EAX),
		  "=b"	(Features->Std.EBX),
		  "=c"	(Features->Std.ECX),
		  "=d"	(Features->Std.EDX)
		: "a" (0x1)
	);
	if (Features->Basic.LargestStdFunc >= 0x5) {
		asm volatile
		(
			"cpuid"
			: "=a"	(Features->MWait.EAX),
			  "=b"	(Features->MWait.EBX),
			  "=c"	(Features->MWait.ECX),
			  "=d"	(Features->MWait.EDX)
			: "a" (0x5)
		);
	}
	if (Features->Basic.LargestStdFunc >= 0x6) {
		asm volatile
		(
			"cpuid"
			: "=a"	(Features->Power.EAX),
			  "=b"	(Features->Power.EBX),
			  "=c"	(Features->Power.ECX),
			  "=d"	(Features->Power.EDX)
			: "a" (0x6)
		);
	}
	if (Features->Basic.LargestStdFunc >= 0x7) {
		asm volatile
		(
			"xor	%%ebx, %%ebx"	"\n\t"
			"xor	%%ecx, %%ecx"	"\n\t"
			"xor	%%edx, %%edx"	"\n\t"
			"cpuid"
			: "=a"	(Features->ExtFeature.EAX),
			  "=b"	(Features->ExtFeature.EBX),
			  "=c"	(Features->ExtFeature.ECX),
			  "=d"	(Features->ExtFeature.EDX)
			: "a" (0x7)
		);
	}
	asm volatile
	(
		"cpuid"
		: "=c"	(Features->ExtInfo.ECX),
		  "=d"	(Features->ExtInfo.EDX)
		: "a" (0x80000001)
	);
	asm volatile
	(
		"cpuid"
		: "=a"	(Features->Basic.LargestExtFunc)
		: "a" (0x80000000)
	);
	if (Features->Basic.LargestExtFunc >= 0x80000007) {
		asm volatile
		(
			"cpuid"			"\n\t"
			"and	$0x100, %%edx"	"\n\t"
			"shr	$8, %%edx"
			: "=d"	(Features->AdvPower.EDX.Inv_TSC)
			: "a" (0x80000007)
		);
	}
	if (!strncmp(Features->VendorID, VENDOR_INTEL, 12)) {
		asm volatile
		(
			"cpuid"
			: "=a"	(Features->PerfMon.EAX),
			  "=b"	(Features->PerfMon.EBX),
			  "=c"	(Features->PerfMon.ECX),
			  "=d"	(Features->PerfMon.EDX)
			: "a" (0xa)
		);
	}
}

size_t jsonStringify(PROC *Proc, char *jsonStr)
{
    size_t fullLen = sprintf(jsonStr,
    "{"
	"\"Processor\":\"%s\","			\
	"\"VendorID\":\"%s\","			\
	"\"Signature\":"			\
	"{"					\
		"\"ExtFamily\":\"%1X\","	\
		"\"Family\":\"%1X\","		\
		"\"ExtModel\":\"%1X\","		\
		"\"Model\":\"%1X\""		\
	"},"					\
	"\"MaxCore\":\"%hu\","			\
	"\"Stepping\":\"%u\","			\
	"\"Instruction\":"			\
	"{"					\
		"\"3DNow\":\"%s\","		\
		"\"3DNowEx\":\"%s\","		\
		"\"AES\":\"%s\","		\
		"\"AVX\":\"%s\","		\
		"\"AVX2\":\"%s\","		\
		"\"BMI1\":\"%s\","		\
		"\"BMI2\":\"%s\","		\
		"\"CLFSH\":\"%s\","		\
		"\"CMOV\":\"%s\","		\
		"\"CMPXCH8\":\"%s\","		\
		"\"CMPXCH16\":\"%s\","		\
		"\"F16C\":\"%s\","		\
		"\"FPU\":\"%s\","		\
		"\"FXSR\":\"%s\","		\
		"\"LAHFSAHF\":\"%s\","		\
		"\"MMX\":\"%s\","		\
		"\"ExtMMX\":\"%s\","		\
		"\"MONITOR\":\"%s\","		\
		"\"MOVBE\":\"%s\","		\
		"\"PCLMULDQ\":\"%s\","		\
		"\"POPCNT\":\"%s\","		\
		"\"RDRAND\":\"%s\","		\
		"\"RDTSCP\":\"%s\","		\
		"\"SEP\":\"%s\","		\
		"\"SSE\":\"%s\","		\
		"\"SSE2\":\"%s\","		\
		"\"SSE3\":\"%s\","		\
		"\"SSSE3\":\"%s\","		\
		"\"SSE41\":\"%s\","		\
		"\"SSE4A\":\"%s\","		\
		"\"SSE42\":\"%s\","		\
		"\"SYSCALL\":\"%s\""		\
	"},"					\
	"\"Feature\":"				\
	"{"					\
		"\"1GB_PAGES\":\"%s\","		\
		"\"100MHzStep\":\"%s\","	\
		"\"ACPI\":\"%s\","		\
		"\"APIC\":\"%s\","		\
		"\"CMP_Legacy\":\"%s\","	\
		"\"CNXT_ID\":\"%s\","		\
		"\"DCA\":\"%s\","		\
		"\"DebugExt\":\"%s\","		\
		"\"PEBS\":\"%s\","		\
		"\"DS_CPL\":\"%s\","		\
		"\"DTES64\":\"%s\","		\
		"\"FastString\":\"%s\","	\
		"\"FMA\":\"%s\","		\
		"\"FMA4\":\"%s\","		\
		"\"HLE\":\"%s\","		\
		"\"LM_IA64\":\"%s\","		\
		"\"LWP\":\"%s\","		\
		"\"MCA\":\"%s\","		\
		"\"MSR\":\"%s\","		\
		"\"MTRR\":\"%s\","		\
		"\"OSXSAVE\":\"%s\","		\
		"\"PAE\":\"%s\","		\
		"\"PAT\":\"%s\","		\
		"\"PBE\":\"%s\","		\
		"\"PCID\":\"%s\","		\
		"\"PDCM\":\"%s\","		\
		"\"PGE\":\"%s\","		\
		"\"PSE\":\"%s\","		\
		"\"PSE36\":\"%s\","		\
		"\"PSN\":\"%s\","		\
		"\"RTM\":\"%s\","		\
		"\"SMX\":\"%s\","		\
		"\"SelfSnoop\":\"%s\","		\
		"\"TSC\":\"%s\","		\
		"\"TSC_Inv\":\"%s\","		\
		"\"TSC_Dead\":\"%s\","		\
		"\"VME\":\"%s\","		\
		"\"VMX\":\"%s\","		\
		"\"x2APIC\":\"%s\","		\
		"\"XD_Bit\":\"%s\","		\
		"\"XSAVE\":\"%s\","		\
		"\"xTPR\":\"%s\""		\
	"}"					\
    "}",
	Proc->Features.Brand,
	Proc->Features.VendorID,
		Proc->Features.Std.EAX.ExtFamily,
		Proc->Features.Std.EAX.Family,
		Proc->Features.Std.EAX.ExtModel,
		Proc->Features.Std.EAX.Model,
	Proc->CPU_Count,
	Proc->Features.Std.EAX.Stepping,
		Proc->Features.ExtInfo.EDX._3DNow ? "true" : "false",
		Proc->Features.ExtInfo.EDX._3DNowEx ? "true" : "false",
		Proc->Features.Std.ECX.AES ? "true" : "false",
		Proc->Features.Std.ECX.AVX ? "true" : "false",
		Proc->Features.ExtFeature.EBX.AVX2 ? "true" : "false",
		Proc->Features.ExtFeature.EBX.BMI1 ? "true" : "false",
		Proc->Features.ExtFeature.EBX.BMI2 ? "true" : "false",
		Proc->Features.Std.EDX.CLFSH ? "true" : "false",
		Proc->Features.Std.EDX.CMOV ? "true" : "false",
		Proc->Features.Std.EDX.CMPXCH8 ? "true" : "false",
		Proc->Features.Std.ECX.CMPXCH16 ? "true" : "false",
		Proc->Features.Std.ECX.F16C ? "true" : "false",
		Proc->Features.Std.EDX.FPU ? "true" : "false",
		Proc->Features.Std.EDX.FXSR ? "true" : "false",
		Proc->Features.ExtInfo.ECX.LAHFSAHF ? "true" : "false",
		Proc->Features.Std.EDX.MMX ? "true" : "false",
		Proc->Features.ExtInfo.EDX.MMX_Ext ? "true" : "false",
		Proc->Features.Std.ECX.MONITOR ? "true" : "false",
		Proc->Features.Std.ECX.MOVBE ? "true" : "false",
		Proc->Features.Std.ECX.PCLMULDQ ? "true" : "false",
		Proc->Features.Std.ECX.POPCNT ? "true" : "false",
		Proc->Features.Std.ECX.RDRAND ? "true" : "false",
		Proc->Features.ExtInfo.EDX.RDTSCP ? "true" : "false",
		Proc->Features.Std.EDX.SEP ? "true" : "false",
		Proc->Features.Std.EDX.SSE ? "true" : "false",
		Proc->Features.Std.EDX.SSE2 ? "true" : "false",
		Proc->Features.Std.ECX.SSE3 ? "true" : "false",
		Proc->Features.Std.ECX.SSSE3 ? "true" : "false",
		Proc->Features.Std.ECX.SSE41 ? "true" : "false",
		Proc->Features.ExtInfo.ECX.SSE4A ? "true" : "false",
		Proc->Features.Std.ECX.SSE42 ? "true" : "false",
		Proc->Features.ExtInfo.EDX.SYSCALL ? "true" : "false",
		Proc->Features.ExtInfo.EDX.PG_1GB ? "true" : "false",
		Proc->Features.AdvPower.EDX._100MHz ? "true" : "false",
		Proc->Features.Std.EDX.ACPI		/* Intel */
		| Proc->Features.AdvPower.EDX.HwPstate	/* AMD */
						? "true" : "false",
		Proc->Features.Std.EDX.APIC ? "true" : "false",
		Proc->Features.ExtInfo.ECX.MP_Mode ? "true" : "false",
		Proc->Features.Std.ECX.CNXT_ID ? "true" : "false",
		Proc->Features.Std.ECX.DCA ? "true" : "false",
		Proc->Features.Std.EDX.DE ? "true" : "false",
		Proc->Features.Std.EDX.DS_PEBS ? "true" : "false",
		Proc->Features.Std.ECX.DS_CPL ? "true" : "false",
		Proc->Features.Std.ECX.DTES64 ? "true" : "false",
		Proc->Features.ExtFeature.EBX.FastStrings ? "true" : "false",
		Proc->Features.Std.ECX.FMA ? "true" : "false",
		Proc->Features.ExtInfo.ECX.FMA4 ? "true" : "false",
		Proc->Features.ExtFeature.EBX.HLE ? "true" : "false",
		Proc->Features.ExtInfo.EDX.IA64 ? "true" : "false",
		Proc->Features.ExtInfo.ECX.LWP ? "true" : "false",
		Proc->Features.Std.EDX.MCA ? "true" : "false",
		Proc->Features.Std.EDX.MSR ? "true" : "false",
		Proc->Features.Std.EDX.MTRR ? "true" : "false",
		Proc->Features.Std.ECX.OSXSAVE ? "true" : "false",
		Proc->Features.Std.EDX.PAE ? "true" : "false",
		Proc->Features.Std.EDX.PAT ? "true" : "false",
		Proc->Features.Std.EDX.PBE ? "true" : "false",
		Proc->Features.Std.ECX.PCID ? "true" : "false",
		Proc->Features.Std.ECX.PDCM ? "true" : "false",
		Proc->Features.Std.EDX.PGE ? "true" : "false",
		Proc->Features.Std.EDX.PSE ? "true" : "false",
		Proc->Features.Std.EDX.PSE36 ? "true" : "false",
		Proc->Features.Std.EDX.PSN ? "true" : "false",
		Proc->Features.ExtFeature.EBX.RTM ? "true" : "false",
		Proc->Features.Std.ECX.SMX ? "true" : "false",
		Proc->Features.Std.EDX.SS ? "true" : "false",
		Proc->Features.Std.EDX.TSC ? "true" : "false",
		Proc->Features.AdvPower.EDX.Inv_TSC ? "true" : "false",
		Proc->Features.Std.ECX.TSCDEAD ? "true" : "false",
		Proc->Features.Std.EDX.VME ? "true" : "false",
		Proc->Features.Std.ECX.VMX ? "true" : "false",
		Proc->Features.Std.ECX.x2APIC ? "true" : "false",
		Proc->Features.ExtInfo.EDX.XD_Bit ? "true" : "false",
		Proc->Features.Std.ECX.XSAVE ? "true" : "false",
		Proc->Features.Std.ECX.xTPR ? "true" : "false"	);
    return(fullLen);
}

int main(int argc, char *argv[])
{
    unsigned long vmSize = sizeof(PROC);
    char *jsonString = NULL;
    int ret = -1;

    vmSize = PAGE_SIZE * ((vmSize / PAGE_SIZE) + ((vmSize % PAGE_SIZE) ? 1:0));
    PROC *Proc __attribute__ ((aligned (64))) = NULL;

    if (!((Proc = malloc(vmSize))) || (!(jsonString = malloc(PAGE_SIZE))))
	ret = -1;
    else {
	memset(Proc, 0, vmSize);
	memset(jsonString, 0, PAGE_SIZE);

	Proc_Features(&Proc->Features);
	Proc_Brand(Proc->Features.Brand);

	if (!strncmp(Proc->Features.VendorID, VENDOR_INTEL, 12))
		Intel_Core_Count(&Proc->CPU_Count);
	if (!strncmp(Proc->Features.VendorID, VENDOR_AMD, 12)) {
		if (Proc->Features.Std.EDX.HTT)
			Proc->CPU_Count = Proc->Features.Std.EBX.MaxThread;
		else if (Proc->Features.Basic.LargestExtFunc >= 0x80000008)
			AMD_Core_Count(&Proc->CPU_Count);
		else
			Proc->CPU_Count = 1;
	}
	if (jsonStringify(Proc, jsonString) > 0) {
		if (argc == 3) {
			char *output = NULL;
			FILE *fd = NULL;
			if ((argv[1][0] == '-') && (argv[1][1] == 'o')
			&& ((output = argv[2]) != NULL)) {
				if ((fd = fopen(output, "w")) != NULL) {
					fprintf(fd, "%s", jsonString);
					fclose(fd);
					ret = 0;
				} else
					ret = -3;
			} else
					ret = -3;
		} else {
			printf("%s\n", jsonString);
			ret = 0;
		}
	} else
		ret = -2;
    }
    if (Proc != NULL)
	free(Proc);
    if (jsonString != NULL)
	free(jsonString);

    return(ret);
}

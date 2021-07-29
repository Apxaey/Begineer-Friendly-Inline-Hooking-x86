#include "Hooker.hpp"

//not going to add comments, watch my video

 RelHook::RelHook(const PVOID t, const PVOID h) : Addr{ {t}, {h}, {nullptr} } {
	Addr[Trampoline] = VirtualAlloc(NULL, 50, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	VirtualProtect(Addr[Target], JmpSize, PAGE_EXECUTE_READWRITE, &TargetP);
};

 RelHook::~RelHook()
 {
	 if (IsHooked)
		 Unhook();

	 VirtualFree(Addr[Trampoline], 0, MEM_RELEASE);
 }

 PVOID RelHook::Hook()
 {
	 std::for_each(Addr, Addr + sizeof(Addr) / sizeof(PVOID), [this](PVOID u)
		 { assert(IsValidMemory((ULONG)u, JmpSize) != FALSE && "Hook Address/Addresses Invalid"); });

	 memcpy(&OriginalBytes, Addr[Target], sizeof(OriginalBytes));


#ifdef _DEBUG
	 std::cout << std::hex << "Original Function Address:" << Addr[Target] << std::endl;
	 std::cout << std::hex << "Redirected Function Address:" << Addr[Redirected] << std::endl;
	 std::cout << std::hex << "Trampoline Address:" << Addr[Trampoline] << std::endl;
#endif
	 MakeTrampoline();
	 MakeRedirect();

	 return IsHooked = true, Addr[Trampoline];
 }

 bool RelHook::Unhook()
 {
	 PrologueBytes OrigFunct;
	 memcpy(&OrigFunct, (PVOID)((ULONG)Addr[Trampoline] + JmpSize), sizeof(OrigFunct));
	 ULONG* OrigFunctAddress = (ULONG*)(OrigFunct.p.addr + JmpSize + (ULONG)Addr[Trampoline]);
	 InterlockedExchange64((LONGLONG*)OrigFunctAddress, OriginalBytes.All_Bytes);
	 VirtualProtect(Addr[Target], JmpSize, TargetP, NULL);
	 return IsHooked = false, true;
 }

 void RelHook::MakeTrampoline()
 {
	 memcpy(Addr[Trampoline], Addr[Target], JmpSize);
	 *((CHAR*)((ULONG)Addr[Trampoline] + JmpSize)) = JmpOpcode;
	 *((ULONG*)((ULONG)Addr[Trampoline] + JmpSize + 1)) = JmpDistance(Addr[Target], Addr[Trampoline]);
 }

 void RelHook::MakeRedirect()
 {
	 PrologueBytes dummy = OriginalBytes;
	 dummy.p.jmp = JmpOpcode;
	 *(ULONG*)(dummy.bytes + 1) = JmpDistance(Addr[Redirected], Addr[Target]);
	 InterlockedExchange64((volatile LONGLONG*)Addr[Target], dummy.All_Bytes);
 }


ULONG RelHook::JmpDistance(PVOID Mem1, PVOID Mem2)
{
	LONG64 JmpDistance = (LONG64)Mem1 - (LONG64)Mem2 - JmpSize;
	assert((JmpDistance) < 0x7FFFFFFF);
	return JmpDistance;
};

bool RelHook::IsValidMemory(ULONG ptr, ULONG size) {
	MEMORY_BASIC_INFORMATION mi;

	if (VirtualQuery((void*)ptr, &mi, sizeof(mi)) == 0)
		return false;

	if (mi.State != MEM_COMMIT || mi.Protect == PAGE_NOACCESS) return false;

	auto ptr_end = ptr + size;
	auto reg_end = (ULONG)mi.BaseAddress + mi.RegionSize;
	if (ptr_end > reg_end)
		return RelHook::IsValidMemory(reg_end, ptr_end - reg_end);

	return true;
}
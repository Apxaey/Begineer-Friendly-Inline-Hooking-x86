#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <cassert>
#include <algorithm>


__pragma(pack(push, 1)) 
union PrologueBytes {
	struct {
		char jmp;
		ULONG addr;
	} p;
	char bytes[sizeof(long long int)];
	long long int All_Bytes = 0;
};
__pragma(pack(pop))

enum : short {
	Target = 0,
	Redirected,
	Trampoline,
	JmpSize = 0x5,
	JmpOpcode = 0xe9
};


class RelHook { 
public:

	explicit RelHook(const PVOID t, const PVOID h);

	static ULONG JmpDistance(PVOID Mem1, PVOID Mem2);
	static bool IsValidMemory(ULONG ptr, ULONG size);

	LPVOID Hook();

	bool Unhook();

	~RelHook();

private:

	void MakeTrampoline();
	void MakeRedirect();

	PrologueBytes OriginalBytes;
	bool IsHooked = false;
	PVOID Addr[3];

	DWORD TargetP;
};


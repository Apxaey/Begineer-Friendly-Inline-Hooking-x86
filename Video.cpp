#include "Hooker.hpp"

using MsgBoxProto = decltype(&MessageBoxA);
MsgBoxProto MsgBoxTramp;

int __stdcall MsgBoxHook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	lpText = "hook do be workin";
		
		return MsgBoxTramp(hWnd, lpText, lpCaption, uType);
}


int main() {

	auto CallFunct = [=] () -> void
	{
		MessageBoxA(NULL, "normal call", "Normal", MB_OK); 
	};

	HMODULE user32 = GetModuleHandleA("User32.dll");
	FARPROC func = GetProcAddress(user32, "MessageBoxA");


	MsgBoxProto test = (MsgBoxProto)func;

	RelHook hooker(func, MsgBoxHook);

	CallFunct();

	MsgBoxTramp = (MsgBoxProto)hooker.Hook();

	CallFunct();
	hooker.Unhook();

	CallFunct();

	return 0;
}
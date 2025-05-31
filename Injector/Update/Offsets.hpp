#pragma once
#include <iostream>
#include <Windows.h>

#define Hyperion "RobloxPlayerBeta.dll"
inline std::wstring Hyp(Hyperion, Hyperion + strlen(Hyperion));



#define Dll1 "msvcp140.dll"
#define Dll2 "vcruntime140.dll"
#define Dll3 "vcruntime140_1.dll"



// updated for: version-ad3ee47cdc5e44f6
#define REBASE(x) x + (uintptr_t)GetModuleHandle("RobloxPlayerBeta.exe")
namespace Offsets {
	inline uintptr_t O_SetInsert = 0xD77510; 
	inline uintptr_t O_WhitelistedPages = 0x2A3820;
	inline uintptr_t O_PageHash = 0xAA9F8E1B;

	namespace virtuals {
		inline uintptr_t PageShift = 0xc;
		inline uintptr_t kbyeshift = 0x2C;

	}
	namespace BitMap {
		inline uintptr_t Bitmap = 0x2855A8;
		inline uintptr_t BitmapShift = 0x13;
		inline uintptr_t BitmapFieldShift = 0x10;
		inline uintptr_t BitmapHash = 0x27;
	}
	namespace Extraspace {
		inline uintptr_t MaxCap = 0xfffffffffffff000;
		inline uint32_t IDE = 7;

	}
}

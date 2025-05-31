#pragma once
#include <sstream>

#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>
#include <Luau/Bytecode.h>

#include <lapi.h>
#include <lstate.h>
#include <lualib.h>
#include <thread>
#include <zstd/zstd.h>
#include <zstd/xxhash.h>
#include <Update/Offsets.hpp>

inline uintptr_t bitmap = *reinterpret_cast<uintptr_t*>(Offsets::BitMap);
namespace Base {
		static struct SRoblox {

			uintptr_t capabilities = ~0ULL;
			void SetProtoCapabilities(Proto* proto) {
				proto->userdata = &capabilities;
				for (int i = 0; i < proto->sizep; i++)
				{
					SetProtoCapabilities(proto->p[i]);
				}
			}

			void SetThreadCap(lua_State* l, int lvl, uintptr_t c) {
				auto extraSpace = (uintptr_t)(l->userdata);
				*reinterpret_cast<uintptr_t*>(extraSpace + 0x48) = c;
				*reinterpret_cast<uintptr_t*>(extraSpace + 0x30) = lvl;
			}

			__forceinline void PatchCFG(uintptr_t address) {
				uintptr_t byteOffset = (address >> 0x13);
				uintptr_t bitOffset = (address >> 0x10) & 7;

				uint8_t* Cache = (uint8_t*)(bitmap + byteOffset);

				DWORD oldProtect;
				VirtualProtect(Cache, 1, PAGE_READWRITE, &oldProtect);

				*Cache |= (1 << bitOffset);

				VirtualProtect(Cache, 1, oldProtect, &oldProtect);
			}


	};



		inline SRoblox* Roblox = new SRoblox();



}
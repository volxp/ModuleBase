#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

struct lua_State;

#define REBASE(x) x + (uintptr_t)GetModuleHandle(nullptr)
#define REBASEHYPERION(x) x + (uintptr_t)GetModuleHandle("RobloxPlayerBeta.dll")


namespace Offsets {
	inline const uintptr_t LuaO_NilObject = REBASE(0x468DCA8);
	inline const uintptr_t LuaH_DummyNode = REBASE(0x468D6C8);
	inline const uintptr_t Luau_Execute = REBASE(0x275D280);
	inline const uintptr_t LockViolationInstanceCrash = REBASE(0x5F4A5A8);
	inline const uintptr_t Print = REBASE(0x15469F0);
	inline const uintptr_t GetProperty = REBASE(0xA3DDB0);
	inline const uintptr_t GetGlobalState = REBASE(0xDA0660);
	inline const uintptr_t DecryptLuaState = REBASE(0xB25660);
	inline const uintptr_t PushInstance = REBASE(0xE7CBC0);
	inline const uintptr_t LuaVM__Load = REBASE(0xB28790);
	inline const uintptr_t Task__Defer = REBASE(0xFC9CA0);//
	inline const uintptr_t FireTouchInterest = REBASE(0x141B380);
	inline const uintptr_t FireProximityPrompt = REBASE(0x1D236A0);
	inline const uintptr_t RequestCode = REBASE(0x8EBD60);
	inline const uintptr_t GetCurrentThreadId = REBASE(0x37F55A0);
	inline const uintptr_t IdentityPtr = REBASE(0x6304418);
	inline const uintptr_t LuaD_throw = REBASE(0x272A4B0);
	inline const uintptr_t RawScheduler = REBASE(0x67AB9E8);
	inline const uintptr_t KTable = REBASE(0x62D04B0);



	// FIRECLICKDETECTOR
	inline const uintptr_t FireMouseClick = REBASE(0x1C4E4E0);///
	inline const uintptr_t FireRightMouseClick = REBASE(0x1C4E680);///
	inline const uintptr_t FireMouseHoverEnter = REBASE(0x1C4FA80);///
	inline const uintptr_t FireMouseHoverLeave = REBASE(0x1C4FC20);///

	inline const uintptr_t BitMap = REBASEHYPERION(0x2855A8);

	inline const uintptr_t GlobalState = 0x140;///
	inline const uintptr_t EncryptedState = 0x88;///
	inline const uintptr_t ScriptContextStart = 0x1F8; ///

	inline const uintptr_t FakeDataModel = REBASE(0x66EA5E8);///
	inline const uintptr_t FakeDataModelToDataModel = 0x1B8;///

	inline const uintptr_t ScriptContext = 944;/// 3b0
	inline const uintptr_t ClassDescriptor = 0x18;///
	inline const uintptr_t PropertyDescriptor = 0x3B8; // --> GetProtperty -> OFF_
	inline const uintptr_t ClassName = 0x8;///
	inline const uintptr_t Name = 0x78;///
	inline const uintptr_t Children = 0x80;///
	inline const uintptr_t LocalScriptEmbedded = 0x1B0;
	inline const uintptr_t LocalScriptHash = 0x1C0;
	inline const uintptr_t ModuleScriptEmbedded = 0x158;
	inline const uintptr_t ModuleScriptHash = 0x180;

	inline const uintptr_t RunContext = 0x150;///
	inline const uintptr_t GameLoaded = 0x650; // 
	inline const uintptr_t weak_thread_node = 0x188;///
	inline const uintptr_t weak_thread_ref = 0x8;///
	inline const uintptr_t weak_thread_ref_live = 0x20;///
	inline const uintptr_t weak_thread_ref_live_thread = 0x8;///



	inline const uintptr_t Identity = 0x30;///
	inline const uintptr_t Capabilities = 0x48;///


	inline const uintptr_t FpsCap = 0x1B0;///
	inline const uintptr_t JobStart = 0x1D0;///
	inline const uintptr_t JobName = 0x18;///

}
namespace Globals {
	inline uintptr_t LuaState;
	inline uintptr_t DataModel;
	inline lua_State* exploitThread;
}
namespace RBX {
	using TPrint = void(__fastcall*)(int, const char*);
	inline auto Print = reinterpret_cast<TPrint>(Offsets::Print);

	using TLuaVM__Load = int(__fastcall*)(lua_State*, void*, const char*, int);
	inline auto LuaVM__Load = reinterpret_cast<TLuaVM__Load>(Offsets::LuaVM__Load);

	using TTask__Defer = int(__fastcall*)(lua_State*);
	inline auto Task__Defer = reinterpret_cast<TTask__Defer>(Offsets::Task__Defer);

	using TGetGlobalState = uintptr_t(__fastcall*)(uintptr_t, int32_t*, uintptr_t*);
	inline auto GetGlobalState = reinterpret_cast<TGetGlobalState>(Offsets::GetGlobalState);

	using TDecryptLuaState = uintptr_t(__fastcall*)(uintptr_t);
	inline auto DecryptLuaState = reinterpret_cast<TDecryptLuaState>(Offsets::DecryptLuaState);

	using TPushInstance = void(__fastcall*)(lua_State* state, void* instance);
	inline auto PushInstance = reinterpret_cast<TPushInstance>(Offsets::PushInstance);

	using TLuaD_throw = void(__fastcall*)(lua_State*, int);
	inline auto LuaD_throw = reinterpret_cast<TLuaD_throw>(Offsets::LuaD_throw);

	using TGetProperty = uintptr_t * (__thiscall*)(uintptr_t, uintptr_t*);
	inline auto GetProperty = reinterpret_cast<TGetProperty>(Offsets::GetProperty);

	using TFireTouchInterest = void(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, bool, bool);
	inline auto FireTouchInterest = reinterpret_cast<TFireTouchInterest>(Offsets::FireTouchInterest);

	using TFireProxmityPrompt = std::uintptr_t(__fastcall*)(std::uintptr_t prompt);
	inline auto FireProximityPrompt = reinterpret_cast<TFireProxmityPrompt>(Offsets::FireProximityPrompt);

	using TRequestCode = uintptr_t(__fastcall*)(uintptr_t protected_string_ref, uintptr_t script);
	inline auto RequestCode = reinterpret_cast<TRequestCode>(Offsets::RequestCode);

	using TFireMouseClick = void(__fastcall*)(__int64 a1, float a2, __int64 a3);
	inline auto FireMouseClick = reinterpret_cast<TFireMouseClick>(Offsets::FireMouseClick);

	using TFireRightMouseClick = void(__fastcall*)(__int64 a1, float a2, __int64 a3);
	inline auto FireRightMouseClick = reinterpret_cast<TFireRightMouseClick>(Offsets::FireRightMouseClick);

	using TFireMouseHoverEnter = void(__fastcall*)(__int64 a1, __int64 a2);
	inline auto FireMouseHoverEnter = reinterpret_cast<TFireMouseHoverEnter>(Offsets::FireMouseHoverEnter);

	using TFireMouseHoverLeave = void(__fastcall*)(__int64 a1, __int64 a2);
	inline auto FireMouseHoverLeave = reinterpret_cast<TFireMouseHoverLeave>(Offsets::FireMouseHoverLeave);


}
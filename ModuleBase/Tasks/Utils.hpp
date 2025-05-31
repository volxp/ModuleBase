#pragma once
#include <Execution/Execution.hpp>

namespace Utils {

	struct STask {
		inline uintptr_t GetDataModel() {
			uintptr_t fakeDm = *(uintptr_t*)Offsets::FakeDataModel;
			uintptr_t Dm = *(uintptr_t*)(fakeDm + Offsets::FakeDataModelToDataModel);

			uintptr_t nameptr = *(uintptr_t*)(Dm + Offsets::Name);

			std::string dataModelName = *(std::string*)nameptr;
			if (dataModelName == "LuaApp") {
				return 0x0;
			}
			std::ostringstream ss;
			ss << "DataModel: " << Dm;
			RBX::Print(1, ss.str().c_str());
			return Dm;
		}

		inline uintptr_t GetScriptContext(uintptr_t Dm) {
			uintptr_t childrenC = *(uintptr_t*)(Dm + Offsets::Children);
			uintptr_t children = *(uintptr_t*)childrenC;
			uintptr_t ScriptContext = *(uintptr_t*)(children + Offsets::ScriptContext);

			std::ostringstream ss;
			ss << "ScriptContext: " << ScriptContext;
			RBX::Print(1, ss.str().c_str());
			return ScriptContext;
		}

		inline uintptr_t GetGlobalState(uintptr_t ScriptContext) {
			int32_t i = 0;
			uintptr_t a = {};
			return RBX::GetGlobalState(ScriptContext, &i, &a);
		}

		inline uintptr_t DecryptLuaState(uintptr_t encryptedState) {
			return RBX::DecryptLuaState(encryptedState);
		}

		inline uintptr_t GetLuaState(uintptr_t DataModel) {
			uintptr_t luaState;

			uintptr_t ScriptContext = GetScriptContext(DataModel);
			if (!ScriptContext)
				return 0x0;
			*reinterpret_cast<BYTE*>(ScriptContext + Offsets::Require_bypass) = 1;
			uintptr_t GlobalState = GetGlobalState(ScriptContext + Offsets::GlobalState);
			luaState = DecryptLuaState(GlobalState + Offsets::EncryptedState);

			return luaState;
		}

		inline bool CreateThread() {
			
			
			lua_gc((lua_State*)Globals::LuaState, LUA_GCSTOP, 0);
			Globals::exploitThread = lua_newthread((lua_State*)Globals::LuaState);
			lua_ref((lua_State*)Globals::LuaState, -1);
			luaL_sandboxthread(Globals::exploitThread);
			lua_pop((lua_State*)Globals::LuaState, 1);
			lua_gc((lua_State*)Globals::LuaState, LUA_GCRESTART, 0);
			Base::Roblox->SetThreadCap(Globals::exploitThread, 8, ~0ULL);

			return true;
			
		}

		bool isGameLoaded(uintptr_t dm) {
			uint64_t value = *reinterpret_cast<uint64_t*>(dm + Offsets::GameLoaded);
			if (value != 31) {
				return false;
			}
			int val = value;
			std::ostringstream ss;
			ss << "GameLoaded: " << val;
			RBX::Print(1, ss.str().c_str());

			return true;
		}



	};
	inline STask* Task = new STask();
}
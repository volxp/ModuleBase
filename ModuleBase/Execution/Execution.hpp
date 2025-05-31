#pragma once
#include <Tasks/TaskScheduler.hpp>


#define xorstr_(x) x
namespace Execution {
	static struct CBase {
		class CBytecodeEncoder : public Luau::BytecodeEncoder {
			inline void encode(uint32_t* ptr, size_t len) override {
				size_t idx = 0;
				while (idx < len) {
					auto& inst = *(uint8_t*)(ptr + idx);
					auto step = Luau::getOpLength(LuauOpcode(inst));
					inst *= 227;
					idx += step;
				}
			}
		};

		CBytecodeEncoder encoder{};

		std::string CompileSrc(const std::string code) {
			auto compiled = Luau::compile(code, { 1, 1, 2 }, { true, true }, &encoder);

			auto rawSize = compiled.size();
			auto compBound = ZSTD_compressBound(rawSize);
			std::vector<char> output(compBound + 8);

			memcpy(output.data(), xorstr_("RSB1"), 4);
			memcpy(output.data() + 4, &rawSize, sizeof(rawSize));

			auto compSize = ZSTD_compress(output.data() + 8, compBound, compiled.data(), rawSize, ZSTD_maxCLevel());
			auto total = compSize + 8;

			auto hash = XXH32(output.data(), total, 42);
			auto* keys = reinterpret_cast<uint8_t*>(&hash);

			for (size_t i = 0; i < total; ++i) {
				output[i] ^= keys[i % 4] + i * 41;
			}

			return std::string(output.data(), total);
		}

		void Execute(lua_State* L, std::string src) {
			if (!L || src.empty()) return;
			auto data = CompileSrc(src);
			if (data.empty() || data[0] == '\0') {
				return;
			}

			lua_settop(L, 0);
			lua_gc(L, LUA_GCSTOP, 0);

			auto thread = lua_newthread(L);
			luaL_sandboxthread(thread);
			if (!thread) {
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			lua_settop(thread, 0);
			lua_getglobal(thread, xorstr_("task"));

			if (lua_isnil(thread, -1)) {
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			lua_getfield(thread, -1, xorstr_("defer"));

			auto user = reinterpret_cast<uintptr_t>(thread->userdata);
			if (!user) {
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			auto ident = user + Offsets::Identity;
			auto caps = user + Offsets::Capabilities;

			if (ident && caps) {
				*reinterpret_cast<uintptr_t*>(ident) = 8;
				*reinterpret_cast<int64_t*>(caps) = ~0ULL;
			}
			else {
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			auto res = RBX::LuaVM__Load(thread, &data, "[BASE]", 0);
			if (res != LUA_OK) {
				std::string err = luaL_checklstring(thread, -1, nullptr);
				lua_pop(thread, 1);
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			auto* func = clvalue(luaA_toobject(thread, -1));
			if (!func) {
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			Base::Roblox->SetProtoCapabilities(func->l.p);

			if (lua_pcall(thread, 1, 0, 0) != LUA_OK) {
				std::string err = luaL_checklstring(thread, -1, nullptr);
				lua_pop(thread, 1);
				lua_gc(L, LUA_GCRESTART, 0);
				return;
			}

			lua_pop(thread, 1);
			lua_gc(L, LUA_GCRESTART, 0);
		}




	};
	inline CBase* cBase = new CBase();
}
#pragma once
#include <NamedPipe.hpp>
#include "Libs/FileSystem/FileSystem.hpp"
#include <lualib.h>


#define REGISTERFUNCTION(name, func) {name, func}
#define END_REGISTRATION {NULL, NULL}


// THIS ENVIRONMENT IS FROM BYTECODE'S MODULE!

namespace Environment {

	static const struct luaL_Reg Lib[] = {
	REGISTERFUNCTION("readfile", Filesystem::readfile),
	REGISTERFUNCTION("listfiles", Filesystem::listfiles),
	REGISTERFUNCTION("writefile", Filesystem::writefile),
	REGISTERFUNCTION("makefolder", Filesystem::makefolder),
	REGISTERFUNCTION("appendfile", Filesystem::appendfile),
	REGISTERFUNCTION("isfile", Filesystem::isfile),
	REGISTERFUNCTION("isfolder", Filesystem::isfolder),
	REGISTERFUNCTION("delfolder", Filesystem::delfolder),
	REGISTERFUNCTION("delfile", Filesystem::delfile),
	REGISTERFUNCTION("loadfile", Filesystem::loadfile),
	REGISTERFUNCTION("dofile", Filesystem::dofile),
	REGISTERFUNCTION("getcustomasset", Filesystem::getcustomasset),


	END_REGISTRATION,
	};



	struct Init {

		void Env(lua_State* l) {
			lua_newtable(l);
			lua_setglobal(l, "_G");

			lua_newtable(l);
			lua_setglobal(l, "shared");


			lua_pushvalue(l, LUA_GLOBALSINDEX);

			const luaL_Reg* i = Lib;
			for (; i->name; i++) {
				lua_pushcfunction(l, i->func, i->name);
				lua_setfield(l, -2, i->name);
			}

			lua_pop(l, 1);
		}

	};
	inline Init* Initializes = new Init();

}
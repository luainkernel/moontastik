package = "ipparse"
version = "1.0-0"
source = {
   url = "git+https://github.com/luainkernel/moontastik",
   branch = "master"
}
description = {
   summary = "Library to parse network packets",
   detailed = "A library for parsing, packing, and manipulating network packets, designed for Lunatik, but usable in plain LuaJIT/Lua 5.1+.",
   homepage = "https://github.com/luainkernel/moontastik",
   license = "MIT OR GPL-2.0-only"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "make",
   build_target = "all",
   install_target = "install",
   build_variables = {
      NAME = "ipparse",
      LUA_MODULE_DIR = "$(LUADIR)"
   },
   install_variables = {
      LUA_MODULE_DIR = "$(LUADIR)"
   }
}

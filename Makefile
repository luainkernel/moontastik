lua_files:
	moonc -t moontastic_lua/ .

zip: lua_files
	zip -r moontastic_lua.zip moontastic_lua && rm -r moontastic_lua

lua_files:
	moonc -t moontastik_lua/ .
	find . -name install.sh -exec cp {} moontastik_lua/{} \;

zip: lua_files
	zip -r moontastik_lua.zip moontastik_lua && rm -r moontastik_lua

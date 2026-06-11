-- Stub FFI module for Lua 5.1 (non-LuaJIT) environments
-- Provides a minimal FFI-like interface for pack operations

local ffi = {}

-- FFI string conversion (pass-through in Lua 5.1)
function ffi.string(data, len)
  if type(data) == "string" then
    if len then
      return data:sub(1, len)
    end
    return data
  end
  return data
end

-- FFI cast (no-op in pure Lua)
function ffi.cast(ctype, value)
  return value
end

-- FFI new (return empty string for buffer allocation)
function ffi.new(ctype, count)
  if type(count) == "number" then
    return string.rep("\0", count)
  end
  return "\0"
end

-- FFI typeof (return the type as-is)
function ffi.typeof(ctype)
  return ctype
end

return ffi

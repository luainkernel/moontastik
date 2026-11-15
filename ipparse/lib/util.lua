--
-- SPDX-FileCopyrightText: (c) 2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Test harness for the ipparse test suite.
-- Provides the `log` printer, the `test` runner and the per-module `summary`
-- accounting used by `tests/`. Hex conversion helpers live in `ipparse.init`.
-- @module util

local util = {}
util._pass  = 0
util._total = 0

--- Logs a message with a specific prefix.
-- @function log
-- @tparam string what The prefix for the log message (e.g., "info", "error").
-- @tparam ... Additional arguments to log, which will be concatenated with tabs.
-- @usage util.log("info", "This is a message")
-- @usage util.log("error", "An error occurred", "Error message")
function util.log(what, ...)
	print(table.concat({what:upper(), ...}, "\t"))
end

--- Runs a test function and prints the result.
-- @tparam string test_name The name of the test.
-- @tparam function func The test function to run.
-- @usage util.test("Test Name", function() ... end)
function util.test(test_name, func)
	local status, err = pcall(func)
	util._total = util._total + 1
	if status then
		util._pass = util._pass + 1
		util.log("pass", test_name)
	else
		util.log("fail", test_name, err, "\n" .. debug.traceback())
	end
end

--- Prints a per-module summary and resets counters.
-- @tparam string name Module display name.
-- @treturn number passed Number of tests that passed.
-- @treturn number total Total number of tests run.
function util.summary(name)
	local passed, total = util._pass, util._total
	util._last_pass, util._last_total = passed, total
	util._pass, util._total = 0, 0
	print(string.format("  --> %s: %d/%d", name, passed, total))
end

return util


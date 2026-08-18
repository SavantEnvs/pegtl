local t = { 1, 2, 3, ["key"] = "value", nested = { a = 1, b = 2 } }
for i = 1, 10 do
  t[i] = i * i
end
for k, v in pairs(t) do
  print(k, v)
end
local function fact(n)
  if n <= 1 then return 1 end
  return n * fact(n - 1)
end
local s = "hello, \"world\"\n"
local long = [[
multi
line
string
]]
-- a comment
--[[ a
long comment ]]
local mt = setmetatable({}, { __index = function(t, k) return 0 end })
local ok, err = pcall(function() error("boom") end)
print(fact(5), ok, err, #s, long)
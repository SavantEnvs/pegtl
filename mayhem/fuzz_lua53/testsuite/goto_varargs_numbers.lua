local function sum(...)
  local s = 0
  for _, v in ipairs({...}) do s = s + v end
  return s
end
local n = 0xFF + 0x1p4 + 3.14e10
::top::
n = n - 1
if n > 0 then goto top end
print(sum(1,2,3), n)
local openssl = require('openssl')

local tokens = {}

--- Generate a token with `length` entropy.
--- The returned string is encoded in base64 and WILL be longer than specified length.
---@return string
---@nodiscard
function tokens.generateToken(length)
  local rand = openssl.random(length)
  return openssl.base64(rand)
end

return tokens

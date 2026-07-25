local querystring = require('querystring')
local urldecode, urlencode = querystring.urldecode, querystring.urlencode

local function parseCookies(header)
  local result = {}
  if not header then
    return result
  end
  -- TODO: make sure we are parsing cookies right
  for name, value in header:gmatch('%s*([^=;]+)=([^;]+);?%s*') do
    result[name] = urldecode(value)
  end
  return result
end

local set_cookie_attrs = {
  domain = 'Domain',
  expires = 'Expires',
  httpOnly = 'HttpOnly',
  maxAge = 'Max-Age',
  partitioned = 'Partitioned',
  path = 'Path',
  secure = 'Secure',
  sameSite = 'SameSite',
}

---@alias auth.Cookies.attributes {
---   domain?: string,
---   expires?: string,
---   httpOnly?: boolean,
---   maxAge?: number,
---   partitioned?: boolean,
---   path?: string,
---   secure?: boolean,
---   sameSite?: auth.Cookies.attributes.sameSite,
--- }
---@alias auth.Cookies.attributes.sameSite 'Strict' | 'Lax' | 'None'

---@param name string
---@param value string | number
---@param params? auth.Cookies.attributes
local function setCookie(name, value, params)
  value = urlencode(tostring(value))
  local encoded_params = {}
  if params then
    for k, v in pairs(params) do
      local attr_name = assert(set_cookie_attrs[k], 'Invalid cookie attribute ' .. tostring(k))
      if type(v) ~= 'boolean' then
        table.insert(encoded_params, '; ')
        table.insert(encoded_params, attr_name .. '=' .. tostring(v))
      elseif v then
        table.insert(encoded_params, '; ')
        table.insert(encoded_params, attr_name)
      end
    end
  end
  return { 'Set-Cookie', name .. '=' .. value .. table.concat(encoded_params) }
end

return {
  parseCookies = parseCookies,
  setCookie = setCookie,
}

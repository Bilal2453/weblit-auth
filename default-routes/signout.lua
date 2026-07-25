local common = require('../common')

---@type auth.weblit.handler
local function signout(req, res)
  if not req.auth._hasAuthenticated then
    return common.text(res, 400, 'Not logged in')
  end

  common.clearTokens(req, res)
  req.auth._hasAuthenticated = false
  req.auth.session:invalidate()

  res.code = 200
  res.body = ''
end

return signout

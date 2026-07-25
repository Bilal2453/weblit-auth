local parseCookies = require('../../cookies').parseCookies
local common = require('../../common')
local Store = require('../../stores/Store') --[[@as auth.Store]]
local core = require('core')

---@class auth.weblit.options: table
--- The session context options.
---@field contextOptions? auth.SessionContext.options
--- Prevents user agents from accessing any route without valid authentication.
--- - Authorization is still enforced separately.
--- - Routes defined before this middleware may still be accessed.
--- - When not enforced, tokens provided by user agents are still validated and may be rejected access if invalid.
---
--- default: `false`.
---@field redirectUnauthenticated? string
--- The interface used to save persistent data.
--- By default this is initialized to a dummy interface.
---
--- default: `Store`.
---@field store auth.Store

--- The main entry point of the authorization context
--- from a middleware/route handler.
---@class auth.weblit.ReqAuth: luvit.core.Object
---@field new fun(self: self, context: auth.SessionContext, options: auth.weblit.options, req: weblit.req, res: weblit.res): auth.weblit.ReqAuth
---@field store auth.Store
---@field context auth.SessionContext
---@field options auth.weblit.options
---@field session auth.Session?
local ReqAuth = core.Object:extend()

function ReqAuth:initialize(context, options, req, res)
  self.req = assert(req)
  self.res = assert(res)
  self.context = assert(context)
  self.options = assert(options)
  self._hasAuthenticated = false
  self.store = options.store or Store:new()
end

--- Checks the request for a valid session id/token.
---
--- This will automatically add `Set-Cookie` headers
--- in the response if it needs to update the session IDs.
--- If the request is authenticated already, it won't do any further work.
---@return boolean authenticated, string? error
---@nodiscard
function ReqAuth:authenticate()
  if self:isAuthenticated() then
    return true
  end
  local context = self.context

  -- parse cookies
  local cookies = parseCookies(self.req.headers.cookie)
  local token = cookies[context.options.cookies.session_token_name]
  local persistent_token = cookies[context.options.cookies.persistent_token_name]

  -- check provided token
  if not token then
    return false, 'No session ID was provided'
  end
  -- check the session store
  local session, err = context:getSession(token)
  if not session then
    return false, 'Invalid session ID: ' .. tostring(err)
  end

  -- validate the session using the provided token
  local is_valid, valid_err, can_rotate = session:isValid()
  if not is_valid and can_rotate and persistent_token then
    local success, rotation_err = session:rotateToken(persistent_token)
    if not success then
      return false, rotation_err
    end
    -- update user agent's cookies
    common.setTokens(self.req, self.res, session)
  elseif not is_valid then
    return false, valid_err
  end

  -- successful authentication
  self:claimAuthenticated(session)
  return true
end

--- Mark this request as valid, associating it with a valid user session.
--- If you need to check if a request is authenticated, use `ReqAuth:isAuthenticated`.
---
--- This will add `Set-Cookie` headers in the response containing the session secrets.
function ReqAuth:claimAuthenticated(session)
  self._hasAuthenticated = true
  self.session = session
  common.setTokens(self.req, self.res, session)
end

--- Checks whether the request is authenticated and has a valid session or not.
--- In other words, was the request made by the person it claims to be?
---
--- This will automatically add `Set-Cookie` headers
--- in the response if it needs to update the session IDs.
function ReqAuth:isAuthenticated()
  p(not self._hasAuthenticated, not self.session)
  if not self._hasAuthenticated or not self.session then
    return false, 'Not authenticated'
  end
  local is_valid, err, can_rotate = self.session:isValid()
  if is_valid then
    return true
  end

  -- the session is invalid, but we might be able to use
  -- the persistent token to refresh it
  local cookies = parseCookies(self.req.headers.cookie)
  local persistent_token = cookies[self.context.options.cookies.persistent_token_name]
  if not (can_rotate and persistent_token) then
    return false, 'Session is invalid: ' .. tostring(err)
  end
  local success, rotation_err = self.session:rotateToken(persistent_token)
  if not success then
    return false, 'Rotation attempt failed: ' .. tostring(rotation_err)
  end

  common.setTokens(self.req, self.res, self.session)
  return true
end

---@class auth.weblit.req: weblit.req
---@field auth auth.weblit.ReqAuth
---@alias auth.weblit.handler fun(req: auth.weblit.req, res: weblit.res, go: function)

return ReqAuth

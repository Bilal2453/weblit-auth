local core = require('core')
local generateToken = require('./tokens').generateToken
local CacheTable = require('classes/CacheTable')

--- the vararg returns depend on the detected attack type, could be a token or nothing.
---@alias auth.onAttackDetected fun(detection_type: auth.detection_type, session: auth.Session, ...)

---@class auth.SessionContext.options: table
local default_options = {
  --- The session token length (a.k.a session id length) in bytes, this is equal to the entropy length.
  ---
  --- default: `16`.
  ---@type integer
  session_token_len = 16,
  --- The session persistent token length (a.k.a refresh token length), in bytes.
  ---
  --- default: `16`.
  ---@type integer
  persistent_token_len = 16,
  --- The token idle timeout period in seconds.
  --- If the user does not use the session within the specified timeout, the token will expire.
  --- The timeout is refreshed every time the session is used.
  ---
  --- default: `30 * 60` (30 minutes).
  ---@type integer
  idle_timeout = 30 * 60,
  --- The token absolute timeout period in seconds.
  --- The session token will be invalid after this timeout, whether the user is active or not,
  --- for high-security applications, it is recommended to lower this value.
  ---
  --- default: `15 * 24 * 60 * 60` (15 days).
  ---@type integer
  absolute_timeout = 15 * 24 * 60 * 60,
  --- The period in seconds for which used persistent tokens remain valid.
  --- This's intended for eliminating race conditions regarding concurrent requests,
  --- an expired persistent token will remain valid (after being used once already) for this period.
  ---
  --- - Only one more request may reuse an old "graced" persistent token.
  --- - After this period, reusing the same persistent token will trigger a replay-attack detection,
  ---   and invalidate the session.
  ---
  --- default: `30`.
  ---@type integer
  grace_period = 30,
  --- Prevents user agents from accessing any route without valid authentication.
  --- - Authorization is still enforced separately.
  --- - Routes defined before this middleware may still be accessed.
  --- - When not enforced, tokens provided by user agents are still validated and may be rejected access if invalid.
  ---
  --- default: `false`.
  ---@type boolean
  forceAuthentication = false,
  --- A callback that's executed on session hijacking attacks or other suspicious activities.
  ---@type auth.onAttackDetected
  onAttackDetected = function() end,
  --- Options related to creating and storing credential cookies on the user agent.
  ---@type table
  cookies = {
    --- The session token (session id) cookie name.
    --- Keep this general so attackers can't deduce the framework being used.
    ---
    --- default: `"id"`.
    ---@type string
    session_token_name = 'id',
    --- The persistent token (refresh token) cookie name.
    --- Keep this general so attackers can't deduce the framework being used.
    ---
    --- default: `"persistent_id"`.
    ---@type string
    persistent_token_name = 'persistent_id',
    --- Whether the user agent should force a secure connection when sending the credentials,
    --- such as when using `https` or `localhost`.
    --- Setting this to false has great risks and anyone may see and steal the credentials.
    ---
    --- [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#secure).
    --- default: `true`.
    ---@type boolean
    secure = true,
    --- Whether the user agent may send the credentials to other "sites" or not.
    ---
    --- [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value).
    --- default: `"Strict"`.
    --- accepts: `"Strict"`, `"Lax"`, `"None"`.
    ---@type auth.Cookies.attributes.sameSite
    sameSite = 'Strict',
    --- Whether the user agent allows JavaScript to read this cookie.
    --- This is highly advised to be set to true, always.
    ---
    --- [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#httponly)
    --- defaullt: `true`.
    ---@type boolean
    httpOnly = true,
    --- Specifies the path that must exist in the URL for the UA to send this cookie.
    ---
    --- [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#pathpath-value)
    --- default: `"/"`.
    ---@type string
    path = '/',
  },
}

---@class auth.SessionContext: luvit.core.Object
---@field new fun(self: self, options: auth.SessionContext.options): auth.SessionContext
--- in-memory storage of the currently active sessions, includes expired sessions.
---@field sessions CacheTable|{[string]: auth.Session}
--- Current context options and configurations.
--- You may change values anytime at runtime.
---@field options auth.SessionContext.options
local SessionContext = core.Object:extend()

---@param options auth.SessionContext.options?
function SessionContext:initialize(options)
  options = options or {}
  self.options = {}
  -- copy default options, use the provided override instead if provided
  for k, v in pairs(default_options) do
    -- don't override an entire table value, only copy what user provides
    if type(v) == 'table' and type(options[k]) == 'table' then
      local val = {}
      for n, m in pairs(v) do
        if options[k][n] ~= nil then
          val[n] = options[k][n]
        else
          val[n] = m
        end
      end
      self.options[k] = val
    else
      self.options[k] = options[k] or v
    end
  end
  self.sessions = CacheTable:new()
end

--- Generate a secure token with `session_token_len` length.
---@return string token
---@nodiscard
function SessionContext:generateToken()
  return generateToken(self.options.session_token_len)
end

--- Given a session token (session id), match it against the stored sessions.
---@param token string
---@return boolean status
---@return string rejection_msg
---@nodiscard
function SessionContext:verifyToken(token)
  local session = self.sessions[token]
  if not session then
    return false, 'unknown token, authentication is required'
  end
  return session:isValid()
end

--- Given a session token (session id), return the stored session if any.
---@param token string
---@return auth.Session? session
---@return string? error
---@nodiscard
function SessionContext:getSession(token)
  local session = self.sessions[token]
  if not session then
    return nil, 'unknown token, authentication is required'
  end
  return session
end

---@param session auth.Session
---@return boolean success, string? error
function SessionContext:addSession(session)
  local is_valid, err = session:isValid()
  if is_valid then
    self.sessions:set(session.token, session, {
      expiry = session.absoluteTimeout,
    })
    -- self.sessions[session.token] = session
    return true
  else
    return false, err
  end
end

---@param session auth.Session
---@return boolean success
function SessionContext:removeSession(session)
  if self.sessions[session.token] then
    self.sessions[session.token] = nil
    return true
  else
    return false
  end
end

return SessionContext

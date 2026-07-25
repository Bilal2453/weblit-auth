local detection_type = require('./constants').detection_type
local CacheTable = require('classes/CacheTable')
local core = require('core')

--- A web session storing user agent states.
---
--- - The user assigned to this session might or might not be authenticated,
---   that depends on the server implementation.
---@class auth.Session: luvit.core.Object
---@field new fun(self: self, sessionContext: auth.SessionContext): auth.Session
---@field context auth.SessionContext
--- The session token secret (also known as session ID), never expose this!
---@field token string
--- The session persistent token, used by the client to
--- generate new session tokens when the current session token expires.
--- This is only allowed to be used once, then it must be rotated.
---@field persistentToken string
--- Expired persistent tokens are stored for detecting replay attacks.
---@field expiredPersistentTokens CacheTable|{[string]: true}
--- Persistent tokens that are temporarily valid.
--- This prevents race conditions on the client.
---@field gracedPersistentTokens CacheTable|{[string]: true}
--- If a new connection isn't made during this period, token must be regenerated.
---@field idleTimeout integer
--- The period after which this session is invalidated and cannot be reused.
---@field absoluteTimeout integer
--- Whether this session has been manually invalidated, e.x. due to a logout.
--- Use `Session:isValid()` for a more general check.
---@field invalid boolean
--- The user assigned to this session. TODO
---@field user auth.User?
--- The user preferences and information related to this session.
---@field preferences {preferredLanguage: string?, ipAddress: string?, userAgent: string?}
local Session = core.Object:extend()

---@param sessionContext auth.SessionContext
function Session:initialize(sessionContext)
  assert(sessionContext, 'a session context is required')
  self.context = sessionContext
  self.token = sessionContext:generateToken()
  self.persistentToken = sessionContext:generateToken()
  self.expiredPersistentTokens = CacheTable:new()
  self.gracedPersistentTokens = CacheTable:new({
    on_expiry = function(token)
      self.expiredPersistentTokens[token] = true
    end,
  })
  local t = os.time()
  self.idleTimeout = t + sessionContext.options.idle_timeout
  self.absoluteTimeout = t + sessionContext.options.absolute_timeout
  self.invalid = false
  self.user = nil
  self.preferences = {} -- TODO

  sessionContext:addSession(self)
end

--- Given a table that has all the required fields of a session
--- create a new instance of the class with the same provided data.
--- Useful when reconstructing a session class from JSON.
function Session.loadNew(data)
  -- TODO
  error('TODO')
end

--- Generate a new session token.
--- Old token is discarded.
--- You must supply the valid persistent token assigned to this session,
--- reusing an old persistent token will trigger a replay attack detection
--- and will result in the session being completely invalidated.
---@return boolean success, string? error
function Session:rotateToken(persistent_token)
  if self.invalid then
    return false, 'session was invalidated'
  end
  -- verify the persistent token.
  -- on luajit this is a constant time comparison, on other Lua versions it is a potential timing attack vector.
  -- string interning is still a potential timing attack vector, but we can't do anything about that,
  -- and it's an unrealistic attack anyways, the required precision is only obtainable by compromising the CPU itself.
  if self.persistentToken ~= persistent_token then
    if self.expiredPersistentTokens[persistent_token] then
      self:invalidate()
      self.context.options.onAttackDetected(detection_type.persistent_token_replay, self, persistent_token)
      return false, 'an expired persistent token was replayed'
    end
  elseif not self.gracedPersistentTokens[persistent_token] then
    return false, 'invalid persistent token'
  end

  self.context.sessions[self.token] = nil
  self.token = self.context:generateToken()
  return self.context:addSession(self)
  -- self.context.sessions[self.token] = self
end

--- Generate a new persistent token.
--- This is a smart rotation:
---  - the old persistent token is stored for `grace_period` amount of time;
---    the token will be temporarily valid to eliminate race conditions.
---  - after the grace period, the token is added into a cache;
---    which we use for replay attack detection.
---  - the graced token may only be accessed once.
---@return boolean success, string? err_msg
function Session:rotatePersistentToken()
  if self.invalid then
    return false, 'session was invalidated'
  end
  self.gracedPersistentTokens:set(self.persistentToken, true, {
    expiry = os.time() + self.context.options.grace_period,
    remaining_uses = 1,
  })
  self.persistentToken = self.context:generateToken()
  return true
end

--- Checks whether the session is still valid.
--- If not, use the extra string return for the reason.
--- If `can_rotate` return is true, you may use the persistent token to refresh the token
--- revalidating the session.
---@return boolean status
---@return string status_msg
---@return boolean? can_rotate # whether or not you may attempt a token rotation
---@nodiscard
function Session:isValid()
  if self.invalid then
    return false, 'session was invalidated'
  end
  local t = os.time()
  if t > self.idleTimeout or t > self.absoluteTimeout then
    return false, 'token has expired', true
  end
  return true, 'authenticated'
end

--- Sets the session as invalid.
--- Users cannot use this session anymore, and it will never become valid again.
function Session:invalidate()
  self.invalid = true
  self.context.sessions[self.token] = nil
  -- cleared for extra peace of mind
  self.token = ''
  self.persistentToken = ''
end

--- Extend the idle timeout.
--- The current session must be valid to do this operation.
---@return boolean success, string? error
function Session:slideIdleTimeout()
  local is_valid, err = self:isValid()
  if not is_valid then
    return false, err
  end
  self.idleTimeout = self.idleTimeout + self.context.options.idle_timeout
  return true
end

--- Assign a user instance to this session.
--- This is used by the webserver on successful authorizations.
---@param user auth.User
function Session:assignUser(user)
  if not self.user then
    self.user = user
    return true
  else
    return nil, 'a user is already assigned'
  end
end

return Session

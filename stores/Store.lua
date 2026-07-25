local core = require('core')

-- Note: this is just the interface!

--- An abstraction interface for allowing different storage backends.
---@class auth.Store: luvit.core.Object
local Store = core.Object:extend()

--- Get a User object using the username.
---@param username string
---@return auth.User?
---@nodiscard
function Store:fetchByUsername(username) end

-- --- Get a User object using the email.
-- ---@param email string
-- ---@return auth.User?
-- ---@nodiscard
-- function Store:fetchByEmail(email) end

--- Stores a new user. Must have a unique username.
---@param user auth.User
---@return boolean success, string? error
function Store:createUser(user)
  return false, 'NYI'
end

--- Deletes an existing user.
---@param user auth.User
---@return boolean success, string? error
function Store:removeUser(user)
  return false, 'NYI'
end

-- TODO: can't change username?
--- Updates a user instance.
---@param user auth.User
---@return boolean success, string? error
function Store:updateUser(user)
  return false, 'NYI'
end

return Store

local core = require('core')
local fs = require('fs')
local json = require('json')

--- An abstraction interface for allowing different storage backends.
--- This is a simple JSON-based file storage, with no guarantees whatsoever.
--- You are absolutely NOT intended to use this in production.
---@class auth.JsonStore: auth.Store
---@field private data table
---@field private filepath string
local JsonStore = core.Object:extend()

function JsonStore:initialize(filepath)
  self.filepath = filepath
  self.data = {}
  self:_load()
end

--- Load JSON data from disk.
---@return boolean success, string? error
function JsonStore:_load()
  if not fs.existsSync(self.filepath) then
    return false, 'file does not exist'
  end
  local raw, err = fs.readFileSync(self.filepath)
  if not raw then
    return false, err
  end

  local data
  data, _, err = json.decode(raw)
  if not data then
    return false, err
  end

  self.data = data

  return true
end

--- an internal method to save to disk.
--- for simplicity sake, it's called on every add/remove operation.
---@return boolean success, string? error
function JsonStore:_save()
  local success, encoded = pcall(json.encode, self.data)
  if not success then
    return false, encoded --[[@as string]]
  end
  return fs.writeFileSync(self.filepath, encoded --[[@as string]])
end

--- Get a User object using the username.
---@param username string
---@return auth.User?
---@nodiscard
function JsonStore:fetchByUsername(username)
  return self.data[username]
end

-- --- Get a User object using the email.
-- ---@param email string
-- ---@return auth.User?
-- ---@nodiscard
-- function JsonStore:fetchByEmail(email)
--   local lower = email:lower()
--   for _, user in pairs(self.data) do
--     if user.email and user.email:lower() == lower then
--       return user
--     end
--   end
-- end

--- Stores a new user. Must have a unique username.
---@param user auth.User
---@return boolean success, string? error
function JsonStore:createUser(user)
  if self:fetchByUsername(user.username) then
    return false, 'User already exists'
  end
  -- TODO: do we need to guarantee email uniqueness as well?
  self.data[user.username] = user
  return self:_save()
end

--- Deletes an existing user.
---@param user auth.User
---@return boolean success, string? error
function JsonStore:removeUser(user)
  if not self.data[user.username] then
    return false, 'User does not exist'
  end
  self.data[user.username] = nil
  return self:_save()
end

--- Updates a user instance.
---@param user auth.User
---@return boolean success, string? error
function JsonStore:updateUser(user)
  if not self.data[user.username] then
    return false, 'User does not exist'
  end
  self.data[user.username] = user
  return self:_save()
end

return JsonStore

local core = require('core')

-- TODO: emails?

--- Represent an authenticated user agent.
---@class auth.User: luvit.core.Object
---@field new fun(self: self, data: {username: string, password: string}): auth.User
---@field username string
---@field password string
local User = core.Object:extend()

function User:initialize(data)
  self.username = assert(data.username, 'A username is required'):lower()
  self.password = assert(data.password, 'A password is required')
end

function User.meta:__tojson()
  return require('json').encode({
    username = self.username,
    password = self.password,
  })
end

return User

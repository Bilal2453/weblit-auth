local sqlite = require('sqlite3')
local core = require('core')
local User = require('../User')

local SCHEMA_VERSION = 1

--- A storage backend that utilizes Sqlite3 databases using the ljsqlite3 driver.
---@class auth.Sqlite3Store: auth.Store
---@field private filepath string
---@field private conn userdata | unknown
---@field private stmts table
local Sqlite3Store = core.Object:extend()

function Sqlite3Store:initialize(sqlite_path)
  self.conn = sqlite.open(sqlite_path)
  self:_schema()
  self:_prepare()
end

function Sqlite3Store:_schema()
  local user_version = self.conn:exec('PRAGMA user_version')[1][1]
  if user_version > 0 then
    return
  end
  self.conn:exec[[
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  ]]
  self.conn:exec('PRAGMA user_version = ' .. SCHEMA_VERSION)
end

function Sqlite3Store:_prepare()
  self.stmts = {
    fetchByUsername = self.conn:prepare('SELECT * FROM users WHERE username==? '),
    deleteByUsername = self.conn:prepare('DELETE FROM users WHERE username==?'),
    updateByUsername = self.conn:prepare('UPDATE users SET username=?, password=? WHERE username==?'),
    createUser = self.conn:prepare('INSERT INTO users(username, password) VALUES(?, ?)'),
  }
end

function Sqlite3Store:_exec(stmt, ...)
  stmt:reset()
  stmt:bind(...)
  return pcall(stmt.step, stmt)
end

--- Get a User object using the username.
---@param username string
---@return auth.User?
---@nodiscard
function Sqlite3Store:fetchByUsername(username)
  local res, n = self.stmts.fetchByUsername:reset():bind(username):resultset()
  if n <= 0 then
    return
  end
  local u, p = res.username[1], res.password[1]
  return User:new({
    username = u,
    password = p,
  })
end

--- Stores a new user. Must have a unique username.
---@param user auth.User
---@return boolean success, string? error
function Sqlite3Store:createUser(user)
  if self:fetchByUsername(user.username) then
    return false, 'User already exists'
  end
  local success, err = self:_exec(self.stmts.createUser, user.username, user.password)
  if not success then
    return false, err
  end
  return true
end

--- Deletes an existing user.
---@param user auth.User
---@return boolean success, string? error
function Sqlite3Store:removeUser(user)
  if not self:fetchByUsername(user.username) then
    return false, 'User does not exist'
  end
  local success, err = self:_exec(self.stmts.deleteByUsername, user.username)
  if not success then
    return false, err
  end
  return true
end

--- Updates a user instance.
---@param user auth.User
---@return boolean success, string? error
function Sqlite3Store:updateUser(user)
  if not self:fetchByUsername(user.username) then
    return false, 'User does not exist'
  end
  local success, err = self:_exec(self.stmts.updateByUsername, user.username, user.password, user.username)
  if not success then
    return false, err
  end
  return true
end

return Sqlite3Store

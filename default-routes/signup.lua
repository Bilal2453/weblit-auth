local Session = require('../Session')
local User = require('../User')
local common = require('../common')
local passhash = require('passhash')

--- Get the user inputs from the client request
--- could be either JSON or a urlencoded form (HTML forms)
---@param req weblit.req
local function getCreds(req)
  -- parse the request payload, if supported
  local body, err = common.parsebody(req)
  if not body then
    return nil, err
  end
  -- handle multiple fields (e.x. with urlencded body), we only respect first occurrence
  for k, v in pairs(body) do
    if type(v) == 'table' then
      body[k] = v[1]
    end
  end

  -- validate required fields
  local username, password, password_confirmation = body.username, body.password, body.password_confirm
  if not username then
    return nil, 'Missing the username'
  elseif not password then
    return nil, 'Missing the password'
  elseif password_confirmation and password ~= password_confirmation then
    -- we only do password_confirm if it was actually provided by the client
    -- if it wasn't, we assume the client has verified it on their side
    -- this isn't our responsibility, it's just to prevent user mistakes
    return nil, 'The provided password does not match password confirmation'
  end

  return {
    password = password --[[@as string]],
    username = username --[[@as string]],
  }
end

---@type auth.weblit.handler
local function signup(req, res)
  if not req.auth then
    return error('Cannot proceed with signup before initializing the auth middleware')
  end
  local context = req.auth.context
  if not context then
    return error('Cannot proceed with signup without an initialized SessionContext')
  end

  if req.auth:isAuthenticated() then
    return common.text(res, 400, 'User is already logged in, logout first')
  end
  local creds, err = getCreds(req)
  if not creds then
    return common.text(res, 400, err)
  end

  local exist_user = req.auth.store:fetchByUsername(creds.username:lower())
  if exist_user then
    return common.text(res, 400, 'A User with the same username already exists')
  end

  local hashed_password, err = passhash.hash(creds.password)
  if not hashed_password then
    return common.text(res, 400, (err or 'Bad password'))
  end

  local user = User:new({
    username = creds.username,
    password = hashed_password,
  })
  local success, err = req.auth.store:createUser(user)
  if not success then
    return common.text(res, 400, err)
  end

  local session = Session:new(context)
  session:assignUser(user)
  success, err = context:addSession(session)
  if not success then
    return common.text(res, 400, err)
  end

  req.auth:claimAuthenticated(session)
  res.code = 201
  res.body = ''
end

return signup

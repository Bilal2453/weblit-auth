local Session = require('../Session')
local common = require('../common')
local passhash = require('passhash')

-- used for doing dummy constant time checks
local dummy_password =
  '$argon2id$v=19$m=20480,t=3,p=1$NTeJ7gVQ3l2b0IM25pZa58NszhIJQZo324QtN0rV704$XcUH1BUiVpJMGuAyITOrCf4WtUesrNrRQNukbDF6xbg'

--- Get the user inputs from the client request
--- could be either JSON or a urlencoded form (HTML forms)
---@param req weblit.req
local function getCreds(req)
  -- parse the request payload, if supported
  local body, err = common.parsebody(req)
  if not body then
    return nil, err
  end
  -- handle multiple fields (e.x. with urlencoded body), we only respect first occurrence
  for k, v in pairs(body) do
    if type(v) == 'table' then
      body[k] = v[1]
    end
  end

  -- validate required fields
  local username, password = body.username, body.password
  if not username then
    return nil, 'Missing the username'
  elseif not password then
    return nil, 'Missing the password'
  end

  return {
    password = password --[[@as string]],
    username = username --[[@as string]],
  }
end

---@type auth.weblit.handler
local function login(req, res)
  if req.auth:isAuthenticated() then
    return common.text(res, 400, 'User is already logged in, logout first')
  end
  local creds, err = getCreds(req)
  if not creds then
    return common.text(res, 400, err)
  end

  -- get the stored user password to match against
  -- we use a dummy password to achieve more constant timing returns
  -- note the user presence check is delayed as well for the same reason
  local user = req.auth.store:fetchByUsername(creds.username)
  local password
  if user then
    password = user.password
  else
    password = dummy_password
  end
  -- does the user exist and the passwords match up?
  local password_match = passhash.verifyHash(password, creds.password)
  if not user or not password_match then
    return common.text(res, 401, "The username doesn't exist or the password is incorrect.")
  end

  -- create and store a new user session
  local session = Session:new(req.auth.context)
  session:assignUser(user)
  local success, err = req.auth.context:addSession(session)
  if not success then
    return common.text(res, 400, err)
  end

  -- update the status
  req.auth:claimAuthenticated(session)
  res.code = 200
  res.body = ''
end

return login

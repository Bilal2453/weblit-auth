local setCookie = require('./cookies').setCookie

--- Respond to a request with a plain text body
---@param res weblit.res
---@param code integer
---@param body string?
local function text(res, code, body)
  res.code = code
  res.headers['Content-Type'] = 'text/plain'
  res.body = body
end

--- Respond to a request with a redirection to `location`
---@param res weblit.res
---@param location string
---@param code integer?
local function redirect(res, location, code)
  res.code = code or 302
  res.headers.Location = location
  res.body = ''
end

local content_type_parser = {
  ['application/x-www-form-urlencoded'] = require('querystring').parse,
  ['application/json'] = require('json').decode,
}

--- Parse a request body according to the Content-Type header, if supported.
---@param req weblit.req
---@return table? result, string content-type_or_error
---@nodiscard
local function parsebody(req)
  if not req.headers['content-type'] or not req.body then
    return nil, 'Unknown content type or missing body'
  end
  local content_type = req.headers['Content-Type']:lower()

  local decode = content_type_parser[content_type]
  if not decode then
    return nil, 'Unsupported content type'
  end

  local dec, err = decode(req.body)
  if not dec then
    return nil, err or 'Could not parse body' --[[@as string]]
  end

  return dec, content_type
end

--- Sends the token and stores it on the User Agent using a cookie
---@param req auth.weblit.req
---@param res weblit.res
---@param session auth.Session
local function setTokens(req, res, session)
  local cookies = req.auth.context.options.cookies
  local id_name = cookies.session_token_name
  local persistent_name = cookies.persistent_token_name
  local attrs = {
    maxAge = session.absoluteTimeout,
    secure = cookies.secure,
    sameSite = cookies.sameSite,
    httpOnly = cookies.httpOnly,
    path = cookies.path,
  }
  table.insert(res.headers, setCookie(id_name, session.token, attrs))
  table.insert(res.headers, setCookie(persistent_name, session.persistentToken, attrs))
end

--- Instructs the User Agent to remove stored cookie credentials
---@param req auth.weblit.req
---@param res weblit.res
local function clearTokens(req, res)
  local cookies = req.auth.context.options.cookies
  local id_name = cookies.session_token_name
  local persistent_name = cookies.persistent_token_name
  local attrs = {
    maxAge = 0,
    secure = true,
    sameSite = 'Strict',
  }
  table.insert(res.headers, setCookie(id_name, '', attrs))
  table.insert(res.headers, setCookie(persistent_name, '', attrs))
end

return {
  text = text,
  redirect = redirect,
  parsebody = parsebody,
  setTokens = setTokens,
  clearTokens = clearTokens,
}

local SessionContext = require('../../SessionContext')
local common = require('../../common')

local ReqAuth = require('./ReqAuth')

--- Prepares the Weblit `req` object to be used by the authentication middleware.
---@param req weblit.req
---@param res weblit.res
---@param options auth.weblit.options
---@param context auth.SessionContext
local function prepareReq(req, res, options, context)
  ---@cast req auth.weblit.req
  req.auth = ReqAuth:new(context, options, req, res)
end

--- Creates and initializes a new SessionContext,
--- returns a middleware that prepares the Weblit request.
---
--- Note: You may only use this once per router.
---@param options auth.weblit.options
---@return function
---@nodiscard
local function init(options)
  local sessionContext = SessionContext:new(options.contextOptions)
  return function(req, res, go)
    -- create `req.auth` fields
    if req.auth then
      return error('a session context is already initialized')
    end
    prepareReq(req, res, options, sessionContext)
    return go()
  end
end

--- Default response on unauthenticated access.
--- This will also tell the UA to clear the session cookies.
---@param req auth.weblit.req
---@param res weblit.res
---@param err string?
local function respondUnauth(req, res, err)
  local redirect_unauthenticated = req.auth and req.auth.options.redirectUnauthenticated
  if redirect_unauthenticated then
    common.redirect(res, redirect_unauthenticated or '/')
  else
    common.text(res, 401, err or 'Unauthenticated')
  end
  common.clearTokens(req, res)
end

--- Validates a request's authority to access the routes beyond this middleware.
--- That is, all middlewares/routes before this are allowed to be accessed by anyone
--- while routes after this middleware will enforce a valid session.
---@param req auth.weblit.req
local function requireAuth(req, res, go)
  if not req.auth then
    return error('Cannot validate a request before initializing the auth middleware')
  end
  local context = req.auth.context
  if not context then
    return error('Cannot validate a request without an initialized SessionContext')
  end
  local success, err = req.auth:authenticate()
  if not success then
    -- TODO: we should probably not send a detailed error message
    return respondUnauth(req, res, err)
  end
  return go()
end

return {
  init = init,
  requireAuth = requireAuth,
}

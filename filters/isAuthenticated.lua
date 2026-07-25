---@param req auth.weblit.req
return function(req)
  return req.auth and req.auth:isAuthenticated()
end

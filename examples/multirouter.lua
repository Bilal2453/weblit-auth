function auth(...)
  local a = ...
  return function(req, _, go)
    req.user = { role = a.role or a.roles[1] }
    return go()
  end
end

local function basic(req, res, go)
  res.code = 200
  if not req.user then
    res.body = 'Hello, anonymous!'
  else
    res.body = 'Hello, ' .. req.user.role .. '!'
  end
end
local publica, publicb, usera, userb, salesa, salesb = basic, basic, basic, basic, basic, basic

local router = require('weblit-router').newRouter
local app = require('weblit-app')

local public = router()
  -- .use(authinit) -- optional
  .route({ path = '/public/a', method = 'GET' }, publica)
  .route({ path = '/public/b', method = 'GET' }, publicb)

local user = router()
  .use(auth({ role = 'user' }))
  .route({ path = '/user/a', method = 'GET' }, usera)
  .route({ path = '/user/b', method = 'GET' }, userb)

local sales = router()
  .use(auth(
    { role = 'admin' },
    -- OR
    { roles = { 'user', 'sales' } }
  ))
  .route({ path = '/sales/a', method = 'GET' }, salesa)
  .route({ path = '/sales/b', method = 'GET' }, salesb)

app
  .use(public.run)
  .use(user.run)
  .use(sales.run)
  .bind({
    host = '127.0.0.1',
    port = 8080,
  })
  .start()

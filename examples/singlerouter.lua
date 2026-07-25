local function authinit(req, _, go)
  req.user = { roles = { 'user', 'invoice' } }
  go()
end

function authfilter(...)
  local a = ...
  return function(req, _, go)
    for i, v in ipairs(req.user.roles) do
      p(v, a.role)
      if v == a.role then
        return true
      end
    end
  end
end

local function basic(req, res, go)
  res.code = 200
  if not req.user then
    res.body = 'Hello, anonymous!'
  else
    res.body = 'Hello, ' .. req.user.roles[1] .. '!'
  end
end
local publica, publicb, usera, userb, salesa, salesb = basic, basic, basic, basic, basic, basic

local app = require('weblit-app')

app
  .use(authinit)
  .route({ path = '/public/a', method = 'GET' }, publica)
  .route({ path = '/public/b', method = 'GET' }, publicb)
  .route({ path = '/user/a', method = 'GET', filter = authfilter({ role = 'user' }) }, usera)
  .route({ path = '/user/b', method = 'GET', filter = authfilter({ role = 'user' }) }, userb)
  .route({ path = '/sales/a', method = 'GET', filter = authfilter({ role = 'sales' }) }, salesa)
  .route({ path = '/sales/b', method = 'GET', filter = authfilter({ role = 'sales' }) }, salesb)
  .bind({
    host = '127.0.0.1',
    port = 8080,
  })
  .start()

local interface = require('./interface/weblit')
local SessionContext = require('./SessionContext')
local cookiesUtil = require('./cookies')
local common = require('./common')
local Store = require('./stores/Store') --[[@as auth.Store]]

-- TODO: add authorization
-- TODO: add documentation and thoroughly test the library before release
-- TODO: finalize the filters interface and figure out what filters we want
-- TODO: add a way to follow redirect on successful login/signup? or keep that for user code?
-- TODO: separate the implementation from weblit interface, allowing for wider integration

return {
  init = interface.init,
  prepareReq = interface.prepareReq,
  requireAuth = interface.requireAuth,

  common = common,
  cookies = cookiesUtil,
  constants = require('./constants'),
  defaultroutes = require('./default-routes'),
  classes = {
    SessionContext = SessionContext,
    Session = require('./Session'),
    User = require('./User'),
    Store = Store,
    JsonStore = require('./stores/JsonStore'),
    Sqlite3Store = require('./stores/Sqlite3Store'),
  },
  filters = require('./filters'),
}

---@enum auth.detection_type
local detection_type = {
  persistent_token_replay = 1,
  mismatched_user_agent = 2, -- TODO: Not Yet Implemented
}

return {
  detection_type = detection_type,
}

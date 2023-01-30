# LoginSystem

A system for securely creating and using logins in a Roblox game

## Example:

```Lua
local LoginSystem = require(ServerStorage:WaitForChild("Packages"):WaitForChild("LoginSystem"))
local ModeratorLogins = LoginSystem.new("Moderator_Login_v1")

local ActiveSessions = {}

AttemptLogin:SetCallback(function(Player, Password)
	local success, response = ModeratorLogins:Login(Player, tostring(Player.UserId), Password)

	return {
		success = success,
		msg = response,
		sessionKey = ModeratorLogins.SessionKeys[Player],
	}
end)

SomeProtectedThing:SetCallback(Player, SessionKey, ...)
	local validate, validateResponse = ModeratorLogins:ValidateLoginSession(Player, SessionKey)
	if not validate then
		return {
			succcess = false,
			msg = validateResponse,
		}
	end

	-- Do the protected thing
	...
end)
```

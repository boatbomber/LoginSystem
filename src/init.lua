-- Services

local DataStoreService = game:GetService("DataStoreService")

-- Modules

local HashLib = require(script.Parent.HashLib)

-----------------------------------------------------------------------------------

local LoginSystem = {}
LoginSystem.__index = LoginSystem

function LoginSystem.new(dataStoreName: string?, config: {}?)
	local loginSystem = setmetatable({
		DataStore = DataStoreService:GetDataStore(dataStoreName or "Login_System"),
		LastAttempt = {},
		Config = {
			-- Sets if only the creator of the account can login
			LOGIN_MUST_BE_CREATOR = true,
			-- Sets if passwords must be 5+ chars, contain uppercase and lowercase, etc (HIGHLY RECCOMENDED)
			PASSWORD_REQUIREMENTS = true,
			-- Chooses which hash function to use from HashLib
			HASH_ALGORITHM = "sha256",
			-- Sets how many characters the hash salt is
			SALT_SIZE = 10,
			-- Sets the rate at which the rate limit multiplies after each failed attempt (prevents brute force)
			RATE_LIMIT_MULTIPLIER = 2.5,
		},
	}, LoginSystem)

	if type(config) == "table" then
		for key, value in config do
			loginSystem.Config[key] = value
		end
	end

	return loginSystem
end

function LoginSystem:CheckForUser(Player, Username)
	return self.DataStore:GetAsync(tostring(Username)) ~= nil
end

function LoginSystem:Register(Player, Username, Password)
	-- Parameter Validation

	if type(Username) ~= "string" then
		return false, "Invalid username: '" .. tostring(Username) .. "'"
	end

	if #Username < 3 then
		return false, "Username must be 3+ characters"
	end

	if type(Password) ~= "string" or #Password < 1 then
		return false, "Invalid password: '" .. tostring(Password) .. "'"
	end

	if self.Config.PASSWORD_REQUIREMENTS then
		if #Password < 5 then
			return false, "Password must be 5+ characters long"
		end

		if not string.find(Password, "%u") then
			return false, "Password must contain uppercase letter(s)"
		end

		if not string.find(Password, "%l") then
			return false, "Password must contain lowercase letter(s)"
		end

		if not string.find(Password, "%d") then
			return false, "Password must contain number(s)"
		end

		if not string.find(Password, "%p") then
			return false, "Password must contain symbol(s)"
		end
	end

	local HashFunction = HashLib[self.Config.HASH_ALGORITHM]
	if not HashFunction then
		return false, "Invalid hash algorithm: '" .. tostring(self.Config.HASH_ALGORITHM) .. "'"
	end

	-- Availability Check

	local PreviousRegister = self.DataStore:GetAsync(Username)

	if PreviousRegister then
		return false, "Username '" .. Username .. "' is already taken"
	end

	-- User Data Creation & Storage

	local SaltTable = {}
	for i = 1, math.abs(self.Config.SALT_SIZE) do
		table.insert(SaltTable, string.char(math.random(33, 126)))
	end
	local Salt = table.concat(SaltTable)

	local DataSaved, Result = pcall(self.DataStore.SetAsync, self.DataStore, Username, {
		Username = Username,
		PasswordHash = HashFunction(Password .. Salt),
		Salt = Salt,
		CreatorId = Player.UserId,
	})

	if not DataSaved then
		return false, "Registering failed: " .. Result
	else
		return true, "Registered successfully"
	end
end

function LoginSystem:Login(Player, Username, Password)
	-- Parameter Validation

	if type(Username) ~= "string" or #Username < 1 then
		warn("Invalid username: " .. type(Username))

		return false, "Invalid username: " .. type(Username)
	end

	if type(Password) ~= "string" or #Password < 1 then
		warn("Invalid password: " .. type(Password))

		return false, "Invalid password: " .. type(Password)
	end

	local HashFunction = HashLib[self.Config.HASH_ALGORITHM]
	if not HashFunction then
		return false, "Invalid hash algorithm: '" .. tostring(self.Config.HASH_ALGORITHM) .. "'"
	end

	-- Rate Limiting

	local Limiter = self.LastAttempt[Username]

	if Limiter then
		local Elapsed = tick() - Limiter.Tick
		if Elapsed < Limiter.Delay then
			return false, "Try again in " .. math.ceil(Limiter.Delay - Elapsed) .. " seconds"
		end
	else
		Limiter = { Tick = 0, Delay = 1 }
	end

	-- Success Check

	local Registered = self.DataStore:GetAsync(Username)
	if not Registered then
		return false, "User not found"
	end

	local PasswordHash = HashFunction(Password .. Registered.Salt)

	if PasswordHash ~= Registered.PasswordHash then
		self.LastAttempt[Username] = {
			Tick = tick(),
			Delay = (Limiter.Delay or 1) * self.Config.RATE_LIMIT_MULTIPLIER,
		}

		return false, "Password is incorrect"
	end

	if self.Config.LOGIN_MUST_BE_CREATOR and Player.UserId ~= Registered.CreatorId then
		-- Username and password are both valid, but access is denied.
		-- We don't return that to them, because that would give away
		-- that they cracked the account credentials!

		self.LastAttempt[Username] = {
			Tick = tick(),
			Delay = (Limiter.Delay or 1) * self.Config.RATE_LIMIT_MULTIPLIER,
		}

		return false, "Password is incorrect"
	end

	self.LastAttempt[Username] = {
		Tick = tick(),
		Delay = 1,
	}

	return true, "Successfully logged in"
end

return LoginSystem

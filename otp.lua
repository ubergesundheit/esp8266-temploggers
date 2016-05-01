-- base32 functions from https://github.com/aiq/basexx
-- Licensed under the MIT License
-- Copyright (c) 2013 aiq
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
-- the Software, and to permit persons to whom the Software is furnished to do so,
-- subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
-- FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
-- COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
-- IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
-- CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
local function number_to_bit( num, length )
   local bits = {}

   while num > 0 do
      local rest = math.floor( num % 2 )
      table.insert( bits, rest )
      num = ( num - rest ) / 2
   end

   while #bits < length do
      table.insert( bits, "0" )
   end

   return string.reverse( table.concat( bits ) )
end

local function pure_from_bit( str )
   return ( str:gsub( '........', function ( cc )
               return string.char( tonumber( cc, 2 ) )
            end ) )
end

local function to_bit( str )
   return ( str:gsub( '.', function ( c )
               local byte = string.byte( c )
               local bits = {}
               for i = 1,8 do
                  table.insert( bits, byte % 2 )
                  byte = math.floor( byte / 2 )
               end
               return table.concat( bits ):reverse()
            end ) )
end

local function divide_string( str, max, fillChar )
   fillChar = fillChar or ""
   local result = {}

   local start = 1
   for i = 1, #str do
      if i % max == 0 then
         table.insert( result, str:sub( start, i ) )
         start = i + 1
      elseif i == #str then
         table.insert( result, str:sub( start, i ) )
      end
   end

   return result
end

local base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local base32PadMap = { "", "======", "====", "===", "=" }

local function from_base32( s )
  local str = string.upper( s )
  local result = {}
  for i = 1, #str do
     local c = string.sub( str, i, i )
     if c ~= '=' then
        local index = string.find( base32Alphabet, c, 1, true )
        if not index then
           return nil, c
        end
        table.insert( result, number_to_bit( index - 1, 5 ) )
     end
  end

  local value = table.concat( result )
  local pad = #value % 8
  return pure_from_bit( string.sub( value, 1, #value - pad ) )
end

local function to_base32(str)
   local bitString = to_bit( str )

   local chunks = divide_string( bitString, 5 )
   local result = {}
   for key,value in ipairs( chunks ) do
      if ( #value < bits ) then
         value = value .. string.rep( '0', 5 - #value )
      end
      local pos = tonumber( value, 2 ) + 1
      table.insert( result, base32Alphabet:sub( pos, pos ) )
   end

   table.insert( result, base32PadMap[ #str % 5 + 1 ] )
   return table.concat( result )
end

-- otp.lua from https://github.com/remjey/luaotp
-- modified by ubergesundheit for nodemcu
-- Licensed under the MIT License
-- Copyright (c) 2015 Jérémy Farnaud
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
local M = {}

-- local bxx = require"basexx"
-- local rand = require"openssl.rand"
-- local hmac = require"openssl.hmac"
local hmac = crypto.new_hash
local HASH_ALGO = "SHA1"

------ Defaults ------

-- local serializer_format_version = 1

-- local default_key_length = 15
local default_digits = 6
local default_period = 30
local default_totp_deviation = 5
local default_hotp_deviation = 20

------ Helper functions ------

-- Formats a counter to a 8-byte string
local function counter_format(n)
  local rt = { 0, 0, 0, 0, 0, 0, 0, 0 }
  local i = 8
  while i > 1 and n > 0 do
    rt[i] = n % 0x100
    n = math.floor(n / 0x100)
    i = i - 1
  end
  return string.char(unpack(rt))
end

-- Generates a one-time password based on a raw key and a counter
local function generate(raw_key, counter, digits)
  local c = counter_format(counter)
  local h = hmac(HASH_ALGO)
  h:update(raw_key)
  h:update(c)
  local s = h:finalize()
  local sign = { s:byte(1,20) }
  local offset = 1 + sign[20] % 0x10
  local r = tostring(
    0x1000000 * (sign[offset] % 0x80) +
    0x10000 * (sign[offset + 1]) +
    0x100 * (sign[offset + 2]) +
    (sign[offset + 3])
  ):sub(-digits)
  if #r < digits then
    r = string.rep("0", digits - #r) .. r
  end
  return r
end

local function percent_encode_char(c)
  return string.format("%%%02X", c:byte())
end

local function url_encode(str)
  -- We use a temporary variable to discard the second result returned by gsub
  local r = str:gsub("[^a-zA-Z0-9.~_-]", percent_encode_char)
  return r
end

-- For testing purposes, we expose the local functions through a private table
-- while keeping them local for better performances

M._private = {
  counter_format = counter_format,
  generate = generate,
  url_encode = url_encode,
}

------ TOTP functions ------

local totpmt = {}

local function new_totp_from_key(key, digits, period)
  local r = {
    type = "totp",
    key = key,
    digits = digits or default_digits,
    period = period or default_period,
    counter = 0,
  }
  setmetatable(r, { __index = totpmt, __tostring = totpmt.serialize })
  return r
end

-- function M.new_totp(key_length, digits, period)
--   return new_totp_from_key(rand.bytes(key_length or default_key_length), digits, period)
-- end

function M.new_totp_from_key(key, digits, period)
  return new_totp_from_key(from_base32(key), digits, period)
  -- return new_totp_from_key(key, digits, period)
end

local function totp_generate(self, deviation)
  local unixtime,u = rtctime.get()
  local counter = math.floor(unixtime / self.period) + (deviation or 0)
  return
    generate(self.key, counter, self.digits),
    counter
end

function totpmt:generate(deviation)
  local r = totp_generate(self, deviation)
  return r -- discard second value
end

function totpmt:verify(code, accepted_deviation)
  if #code ~= self.digits then return false end
  local ad = accepted_deviation or default_totp_deviation
  for d = -ad, ad do
    local verif_code, verif_counter = totp_generate(self, d)
    if verif_counter >= self.counter and code == verif_code then
      self.counter = verif_counter + 1
      return true
    end
  end
  return false
end

-- function totpmt:get_url(issuer, account, issuer_uuid)
--   local key, issuer, account = url_encode(bxx.to_base32(self.key)), url_encode(issuer), url_encode(account)
--   local issuer_uuid = issuer_uuid and url_encode(issuer_uuid) or issuer
--   return table.concat{
--     "otpauth://totp/",
--     issuer, ":", account,
--     "?secret=", key,
--     "&issuer=", issuer_uuid,
--     "&period=", tostring(self.period),
--     "&digits=", tostring(self.digits),
--   }
-- end

-- function totpmt:serialize()
--   return table.concat{
--     "totp:", serializer_format_version,
--     ":", crypto.toBase64(self.key),
--     ":", tostring(self.digits),
--     ":", tostring(self.period),
--     ":", tostring(self.counter),
--     ":"
--   }
-- end

------ HOTP functions ------

local hotpmt = {}

local function new_hotp_from_key(key, digits, counter)
  local r = {
    type = "hotp",
    key = key,
    digits = digits or default_digits,
    counter = counter or 0,
  }
  setmetatable(r, { __index = hotpmt, __tostring = hotpmt.serialize })
  return r
end

-- function M.new_hotp(key_length, digits, counter)
--   return new_hotp_from_key(rand.bytes(key_length or default_key_length), digits, counter)
-- end

-- function M.new_hotp_from_key(key, digits, counter)
--   print(key)
--   local k = from_base32(key)
--   print(k)
--   return new_hotp_from_key(from_base32(key), digits, counter)
-- end

function hotpmt:generate(counter_value)
  local r = generate(self.key, counter_value or self.counter, self.digits)
  if not counter_value then
    self.counter = self.counter + 1
  end
  return r
end

function hotpmt:verify(code, accepted_deviation)
  local counter_max = self.counter + (accepted_deviation or default_hotp_deviation)
  for i = self.counter, counter_max do
    if code == self:generate(i) then
      self.counter = i + 1
      return true
    end
  end
  return false
end

-- function hotpmt:get_url(issuer, account, issuer_uuid)
--   local key, issuer, account = url_encode(bxx.to_base32(self.key)), url_encode(issuer), url_encode(account)
--   local issuer_uuid = issuer_uuid and url_encode(issuer_uuid) or issuer
--   return table.concat{
--     "otpauth://hotp/",
--     issuer, ":", account,
--     "?secret=", key,
--     "&issuer=", issuer_uuid,
--     -- Some clients fail to use the counter correctly, so we give them a future counter to be sure
--     "&counter=", tostring(self.counter + 2),
--     "&digits=", tostring(self.digits),
--   }
-- end

-- function hotpmt:serialize()
--   return table.concat{
--     "hotp:", serializer_format_version,
--     ":", crypto.toBase64(self.key),
--     ":", tostring(self.digits),
--     ":", tostring(self.counter),
--     ":"
--   }
-- end

------ Common functions ------

local function get_key(key)
  return bxx.to_base32(key.key)
end
hotpmt.get_key = get_key
totpmt.get_key = get_key

return M


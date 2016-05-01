-- init.lua

-- Configuration!
DEVICE_SECRET = 'JSONWEBTOKENSECRET'
POST_URL = ''
NTP_IP = 'de.pool.ntp.org' -- or set to your country or simply 'pool.ntp.org'
WIFI_SSID = ''
WIFI_PASS = ''
WIFI_CONFIG = {
  ip="10.0.0.248",
  netmask="255.255.255.0",
  gateway="10.0.0.1"
}
COLLECTION = "some_string"
POST_DELAY = 60000 -- in milliseconds

-- name of the file which does the following:
-- initializes the usesd sensor and implements `getData`
-- must be compiled (ends to .lc)
SENSOR="dummy"

print("Setting up WIFI...")
wifi.setmode(wifi.STATION)
wifi.sta.config(WIFI_SSID, WIFI_PASS)
wifi.sta.setip(WIFI_CONFIG)
wifi.sta.connect()
tmr.alarm(1, 1000, 1, function()
  if wifi.sta.getip()== nil then
    print("IP unavailable, Waiting...")
  else
    tmr.stop(1)
    sntp.sync("de.pool.ntp.org",
      function(unixtime,usec,server)
        rtctime.set(unixtime,usec)
        print(unixtime)
        otp = require("otp")
        totp = otp.new_totp_from_key("N5LDS33PM5SS44TJNBQWQ6DJMM======")
        tmr.alarm(2, 5000, 1, function()
          print(totp:generate())
          print(node.heap())
        end)
      end,
      function() end
    )
  end
end)

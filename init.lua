-- init.lua

-- Configuration!
DEVICE_SECRET = 'JSONWEBTOKENSECRET'
POST_URL = 'http://URL-TO-YOUR-SERVER.COM/PATH-TO-YOUR-ENDPOINT'
NTP_IP = '5.100.133.221'
WIFI_SSID = 'your wifi ssid'
WIFI_PASS = 'your wifi password'
WIFI_CONFIG = {
  ip="192.168.1.248",
  netmask="255.255.255.0",
  gateway="192.168.1.1"
}
COLLECTION = "some_string"
POST_DELAY = 300000 -- in milliseconds

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
    print("Config done, IP is "..wifi.sta.getip())
    dofile(SENSOR..".lc")
    dofile("utils.lc")
    publishStatus()
    -- send data every once in a while (every minute)
    tmr.alarm(2, POST_DELAY, 1, publishStatus)
  end
end)

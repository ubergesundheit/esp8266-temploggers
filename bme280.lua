function getData()
  local p,t1 = bme280.baro()
  local h,t2 = bme280.humi()
  local t = (t1 + t2) / 2
  return {
        temp=(t / 100),
        baro=(p / 1000),
        hum=(h / 1000),
        heap=node.heap()
      }
end

BME_SDA_PIN = 3
BME_SCL_PIN = 4

bme280.init(BME_SDA_PIN, BME_SCL_PIN)

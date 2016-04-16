DHT_PIN = 3 -- where the DHT 22 is connected (GPIO2)

function getData()
  status,temp,humi = dht.read(DHT_PIN)
  if status == dht.OK then
    return {
      temp=temp,
      humi=humi,
      heap=node.heap()
    }
  elseif status == dht.ERROR_CHECKSUM then
    print("dht checksum error")
  elseif status == dht.ERROR_TIMEOUT then
    print("dht timeout")
  end
  return nil
end

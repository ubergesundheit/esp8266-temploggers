FROM node:4-slim

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN npm install -g nodemcu-tool@1.5.0

ENTRYPOINT ["nodemcu-tool", "--port", "/dev/ttyACM0", "--baud", "115200"]

CMD ["terminal"]


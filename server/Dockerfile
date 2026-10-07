FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY src/ src/
# The container must listen on its own interface for the published port to work;
# on a non-loopback bind the proxy fails closed until PROXY_AUTH_TOKEN is set.
ENV HOST=0.0.0.0
EXPOSE 8787
CMD ["node", "src/index.js"]

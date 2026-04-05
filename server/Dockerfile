FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY src/ src/
EXPOSE 8787
CMD ["node", "src/index.js"]

# Stage 1: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
# Delete lock file and regenerate to resolve peer dependency conflicts
RUN rm -f package-lock.json && npm install
COPY . .
RUN npx ng build --configuration production --base-href /

# Stage 2: Serve with nginx
FROM nginx:alpine
COPY --from=build /app/dist/mitre-mitigation-navigator/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

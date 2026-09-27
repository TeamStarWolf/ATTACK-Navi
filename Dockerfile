# Stage 1: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
# Reproducible install from the committed lockfile. The Angular 21 peer-dependency
# conflicts that previously forced a lockfile delete were reconciled in #76, so a
# clean `npm ci` now succeeds and the scanned dependency set matches what ships.
RUN npm ci
COPY . .
RUN npx ng build --configuration production --base-href /

# Stage 2: Serve with nginx
FROM nginx:alpine
COPY --from=build /app/dist/mitre-mitigation-navigator/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

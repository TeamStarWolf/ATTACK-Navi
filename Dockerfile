# Stage 1: Build
# Node 24 (alpine) — Angular 22's CLI requires Node >=22.22.3 / >=24.15.0 / >=26.
FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
# Reproducible install from the committed lockfile: a clean `npm ci` succeeds and
# the scanned dependency set matches what ships.
RUN npm ci
COPY . .
RUN npx ng build --configuration production --base-href /

# Stage 2: Serve with nginx as the unprivileged user 101 on port 8080 (not root on 80)
FROM nginxinc/nginx-unprivileged:alpine
COPY --from=build /app/dist/mitre-mitigation-navigator/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]

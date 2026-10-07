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

# Stage 2: Serve with nginx
FROM nginx:alpine
COPY --from=build /app/dist/mitre-mitigation-navigator/browser /usr/share/nginx/html
# Site config and security-header snippet are envsubst templates: the nginx image's
# entrypoint renders them into /etc/nginx/conf.d at container start, replacing the
# stock default.conf (see the header comment in nginx.conf).
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx-security-headers.conf /etc/nginx/templates/security-headers.inc.template
# Defaults for the placeholders; docker-compose.yml and `docker run -e` override them.
#   PROXY_UPSTREAM        where /api/ is forwarded (the compose proxy service)
#   NGINX_RESOLVER        DNS used to resolve it per request (Docker's embedded DNS)
#   CSP_EXTRA_CONNECT_SRC extra connect-src origins, space separated (default none)
ENV PROXY_UPSTREAM=http://proxy:8787 \
    NGINX_RESOLVER=127.0.0.11 \
    CSP_EXTRA_CONNECT_SRC=""
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

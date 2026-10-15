# Builds both front-ends: the landing + auth site (served at /) and the dashboard (served at /app).
FROM node:22-alpine AS build
WORKDIR /src
# landing + auth
COPY web/package.json web/
RUN cd web && npm install --no-audit --no-fund
COPY web ./web
RUN cd web && npm run build
# dashboard
COPY dashboard/package.json dashboard/
RUN cd dashboard && npm install --no-audit --no-fund
COPY dashboard ./dashboard
RUN cd dashboard && npm run build

FROM nginx:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/web/dist /usr/share/nginx/html
COPY --from=build /src/dashboard/dist /usr/share/nginx/html/app

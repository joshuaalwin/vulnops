# ---- Build stage ----
# INTENTIONAL: node:20-alpine is used here deliberately to carry known CVEs.
# This will cause the Trivy image scan in the Phase 6 CI pipeline to fail,
# demonstrating that the security gate catches vulnerable base images.
# Will be upgraded to a current digest-pinned image once the gate is shown working.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci && npm cache clean --force
COPY . .
RUN npm run build

# ---- Production stage ----
# Pinned to digest — tags are mutable, a compromised upstream image with the
# same tag would be pulled silently. Digest guarantees byte-for-byte identity.
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 AS production

# Security: remove default nginx config
RUN rm -rf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/*

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built frontend from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Security: run nginx as non-root
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Security: Use existing nginx user with proper permissions
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

# Security: Set proper permissions
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d

# Create nginx PID directory
RUN mkdir -p /var/run/nginx && \
    chown -R nginx:nginx /var/run/nginx

USER nginx

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
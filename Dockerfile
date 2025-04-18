# Stage 1: Build the React app
FROM node:23-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json to install dependencies
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the React app for production
RUN npm run build

# Debug: List the build directory contents
RUN ls -la /app/build

# Stage 2: Serve the built app with Nginx
FROM nginx:alpine

# Remove the default Nginx configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy the built files from the builder stage to the Nginx html directory
COPY --from=builder /app/build /usr/share/nginx/html

# Copy the custom nginx.conf
COPY nginx.conf /etc/nginx/nginx.conf

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create a directory for Nginx PID and set permissions
RUN mkdir -p /run/nginx && \
    chown -R appuser:appgroup /run/nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx

# Debug: List the html directory contents and permissions
RUN ls -la /usr/share/nginx/html && \
    ls -la /run/nginx

# Expose port 80
EXPOSE 80

# Run Nginx as the non-root user
USER appuser

# Start Nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]
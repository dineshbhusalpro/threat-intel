FROM nginx:alpine

# Install Node.js for building
RUN apk add --no-cache nodejs npm

WORKDIR /app

# Copy frontend files
COPY package.json ./
COPY index.html ./
COPY network_viz.js ./
COPY style.css ./

# Install dependencies if any
RUN npm install || true

# Copy built files to nginx
RUN cp -r * /usr/share/nginx/html/

# Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
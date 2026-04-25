FROM node:20-alpine

# Install build tools for better-sqlite3
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install --production

# Copy application files
COPY server.js ./
COPY public/ ./public/

# Create data and uploads directories
RUN mkdir -p data uploads

# Set permissions
RUN chown -R node:node /app
USER node

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "server.js"]

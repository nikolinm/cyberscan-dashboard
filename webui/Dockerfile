FROM node:20-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Install Docker CLI so the container can run docker exec commands on host (via mounted docker.sock)
RUN apk add --no-cache docker-cli

# Copy rest of the app code
COPY . .

# Expose the UI port
EXPOSE 2609

# Start the app
CMD [ "node", "app.js" ]



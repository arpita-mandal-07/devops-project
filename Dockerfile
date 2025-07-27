# Base image
FROM node:20-alpine

# Set working directory
WORKDIR /app/project-task-1

# Copy dependencies
COPY project-task-1/package*.json ./
RUN npm install

# Copy source files
COPY project-task-1/. .

# Expose app port (e.g., 3000)
EXPOSE 3000

# Start the app
CMD ["npm", "start"]

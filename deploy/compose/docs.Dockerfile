FROM node:22-slim
WORKDIR /app
COPY docs/package.json docs/package-lock.json ./
RUN npm ci
COPY docs /app
RUN npm run build
EXPOSE 4321
CMD ["npx", "astro", "preview", "--host", "0.0.0.0", "--port", "4321"]

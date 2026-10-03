FROM node:22-slim
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard /app
RUN npm run build
EXPOSE 5173
ENV INSIDIA_DEV_MODE=true
ENV INSIDIA_API_ORIGIN=http://api:8000
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173"]

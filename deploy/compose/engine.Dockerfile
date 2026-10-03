FROM python:3.14-slim

RUN pip install --no-cache-dir uv
WORKDIR /app/engine
COPY engine /app/engine
COPY schema /app/schema
RUN uv sync --frozen --no-dev
ENV INSIDIA_DEV_MODE=true
CMD ["uv", "run", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

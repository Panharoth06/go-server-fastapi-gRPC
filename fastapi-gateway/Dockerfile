FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir \
    "fastapi[standard]>=0.129.0" \
    "grpcio>=1.78.0" \
    "protobuf>=6.31.1" \
    "uvicorn>=0.41.0"

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

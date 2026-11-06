FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
COPY config/ config/
COPY wiki/ wiki/
RUN useradd --no-create-home --uid 10001 app
USER app
CMD ["gunicorn", "--bind", "192.168.1.10:8443", "--certfile", "/certs/tls.crt", "--keyfile", "/certs/tls.key", "--workers", "1", "app.web:create_app()"]

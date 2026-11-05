FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py thermocontrol.py bot_gateway.py ./
COPY test_thermocontrol.py test_bot_gateway.py ./

RUN useradd --create-home --uid 10001 thermocontrol \
    && mkdir -p /app/data \
    && chown -R thermocontrol:thermocontrol /app

USER thermocontrol

CMD ["python", "main.py", "--bot", "--db", "/app/data/thermocontrol.sqlite3", "--key", "/app/data/thermocontrol.key", "--token-file", "/run/secrets/bot_token"]

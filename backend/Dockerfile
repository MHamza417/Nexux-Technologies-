FROM python:3.12-slim

WORKDIR /app

ENV DATABASE_PATH=/data/db.sqlite3

RUN mkdir -p /data

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

VOLUME ["/data"]

CMD ["python", "manage.py", "runserver", "0.0.0.0:5000"]
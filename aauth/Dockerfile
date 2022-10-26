
FROM python:3.8-slim

WORKDIR /app
RUN pip install Flask Flask-SQLAlchemy PyCryptodome PyJWT cachetools cryptography gunicorn
COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:8000", "main:app"]

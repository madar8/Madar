FROM python:3.12-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home madar && mkdir /data && chown madar:madar /data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=madar:madar server.py backup.py wsgi.py gunicorn.conf.py ./
COPY --chown=madar:madar web/ ./web/
USER madar
ENV MADAR_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
VOLUME /data
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:application"]

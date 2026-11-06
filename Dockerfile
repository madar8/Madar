FROM python:3.12-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home madar && mkdir /data && chown madar:madar /data
COPY --chown=madar:madar server.py backup.py ./
COPY --chown=madar:madar web/ ./web/
USER madar
ENV MADAR_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
VOLUME /data
CMD ["python", "server.py", "serve", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 omega && useradd --uid 10001 --gid omega --no-create-home omega
WORKDIR /app
COPY media_worker.py /app/media_worker.py
USER 10001:10001
ENTRYPOINT ["python", "/app/media_worker.py"]

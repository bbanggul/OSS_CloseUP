FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /source
COPY backend/requirements.txt /tmp/backend-requirements.txt
RUN pip install -r /tmp/backend-requirements.txt pytest==9.1.1 httpx==0.28.1

# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Working directory
WORKDIR /app

# Copy requirements files
COPY requirements.txt /app/requirements.txt
COPY requirements_api.txt /app/requirements_api.txt

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir -r /app/requirements_api.txt

# Copy all project files
COPY . /app

# Expose ports
EXPOSE 8000
EXPOSE 8501

# Start FastAPI + Streamlit
CMD ["sh", "-c", "python -m uvicorn api:app --host 0.0.0.0 --port 8000 & streamlit run app.py --server.address=0.0.0.0 --server.port=8501"]
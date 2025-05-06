FROM python:3.9.22-slim-bookworm

# Install system dependencies for SQLCipher
RUN apt-get update && \
    apt-get install -y build-essential libsqlcipher-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN groupadd -r syncauth && useradd -r -g syncauth syncauth

WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app.py .
COPY storage.py .
COPY syncthing_api.py .
COPY static static/
COPY templates templates/

# Create directory for Flask sessions
RUN mkdir -p /data/flask_session

# Environment variables
ENV HOST=0.0.0.0
ENV PORT=5001
ENV DEBUG=False
ENV DATA_DIR=/data
# Remove hardcoded SECRET_KEY - this should be provided at runtime if encryption is desired
# ENV SECRET_KEY="change_this_to_a_secure_key"

# Create data directory for persistent storage and set permissions
RUN mkdir -p /data && \
    chown -R syncauth:syncauth /app /data /data/flask_session && \
    chmod -R 755 /data

VOLUME /data

# Expose the port
EXPOSE 5001

# Switch to non-root user
USER syncauth

# Run the application
CMD ["python", "app.py"]

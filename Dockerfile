FROM python:3.9.22-slim-bullseye

# Install system dependencies for SQLCipher and Node.js/yarn for dev mode
RUN apt-get update && \
    apt-get install -y build-essential libsqlcipher-dev curl gnupg && \
    # Install Node.js and yarn
    curl -sL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    # Enable Corepack for Yarn 3+
    corepack enable && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN groupadd -r syncauth && useradd -r -g syncauth syncauth

# Create required directories and set permissions for Corepack
RUN mkdir -p /home/syncauth/.cache/node/corepack && \
    mkdir -p /home/syncauth/.yarn && \
    chown -R syncauth:syncauth /home/syncauth

WORKDIR /app

# Copy requirements first for better layer caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Add development dependencies
RUN pip install --no-cache-dir watchdog

# Add backend files
COPY backend/app.py backend/
COPY backend/storage.py backend/
COPY backend/syncthing_api.py backend/
COPY backend/static backend/static/
COPY backend/templates backend/templates/

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

# Expose ports - 5001 for Flask, 9000 for Quasar dev server
EXPOSE 5001 9000

# Add entrypoint script to handle dev mode
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

# Switch to non-root user
USER syncauth

# Use entrypoint script instead of direct command
ENTRYPOINT ["/docker-entrypoint.sh"]

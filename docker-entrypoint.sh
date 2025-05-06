#!/bin/bash
set -e

# This function prepares the environment for Quasar but doesn't start it
# (Flask will start Quasar when running in dev mode)
prepare_quasar_env() {
  echo "Preparing Quasar development environment..."
  cd /app/frontend
  # Use corepack to prepare the correct yarn version
  corepack prepare
  # Install dependencies but don't start Quasar
  yarn install
  cd /app
}

# Function to handle termination
cleanup() {
  echo "Shutting down services..."
  exit 0
}

# Set up signal traps
trap cleanup SIGTERM SIGINT

# Main entrypoint logic
if [ "$1" = "--dev" ]; then
  echo "Running in DEVELOPMENT mode"
  # Only prepare the Quasar environment, let Flask start the dev server
  prepare_quasar_env
  # Start Flask in development mode
  cd /app
  python backend/app.py --dev
else
  echo "Running in PRODUCTION mode"
  cd /app
  # Ensure the static files folder exists
  if [ ! -d "frontend/dist/spa" ]; then
    echo "Building Quasar production build..."
    cd /app/frontend
    corepack prepare
    yarn install
    yarn build
    cd /app
  fi
  # Start Flask in production mode
  python backend/app.py
fi

# Keep the container running if anything is still running in background
wait

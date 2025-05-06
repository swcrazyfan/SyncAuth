# SyncAuth - Syncthing Credential Synchronization Manager

SyncAuth is a containerized web application that allows you to synchronize Syncthing GUI credentials across multiple instances. It provides a modern, responsive web interface to manage your master and client Syncthing instances and automate the credential synchronization process.

## Features

- **Master-Client Configuration**: Configure a master Syncthing instance and manage multiple clients
- **Credential Synchronization**: Automatically sync GUI username and password across instances
- **Automatic Scheduled Sync**: Schedule syncs on hourly, daily, or weekly basis, or create a custom schedule
- **Password Management**: Change Syncthing GUI passwords directly from the interface
- **Device Discovery**: Discover Syncthing devices from your master instance
- **Connection Testing**: Verify accessibility of all instances before synchronizing
- **Reactive UI**: Modern Alpine.js-powered interface with real-time updates
- **Database Management**: Options to encrypt, decrypt, reset, or start over with your configuration database
- **Secure Storage**: Optionally encrypt your database with a secret key
- **Mobile-Friendly Design**: Responsive interface works well on desktop and mobile devices

## Requirements

- Docker
- Network access to all Syncthing instances
- API keys for all Syncthing instances

## Quick Start

### Build and Run with Docker

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/SyncAuth.git
   cd SyncAuth
   ```

2. Set up your environment configuration:

   ```bash
   # Copy the example environment file
   cp .env.example .env
   ```

   > **Important**: Once you've started using SyncAuth with a specific SECRET_KEY, 
   > changing it will make your existing database inaccessible.

   Generate a secure key and update your `.env` file:

   **Linux/Mac**:
   ```bash
   # Generate a secure random key
   NEW_KEY=$(openssl rand -hex 32)
   echo "Generated key: $NEW_KEY"
   
   # Manually edit .env and replace the SECRET_KEY line with your new key
   # Or use these commands:
   
   # For Linux:
   # sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
   
   # For macOS:
   # sed -i '' "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
   ```

   **Windows (PowerShell)**:
   ```powershell
   # Generate a secure random key
   $NEW_KEY = (openssl rand -hex 32)
   echo "Generated key: $NEW_KEY"
   
   # Manually edit .env and replace the SECRET_KEY line with your new key
   # Or use this command:
   (Get-Content .env) -replace "^SECRET_KEY=.*", "SECRET_KEY=$NEW_KEY" | Set-Content .env
   ```

   Review your `.env` file and adjust settings as needed.

3. Build the Docker image:
   ```
   docker build -t syncauth .
   ```

4. Run the container:
   ```
   docker run -d \
     --name syncauth \
     -p 5001:5001 \
     -v $(pwd)/docker_data:/data \
     --env-file .env \
     syncauth
   ```

5. Access the web interface at `http://localhost:5001`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Address to bind to | `0.0.0.0` |
| `PORT` | Port to listen on | `5001` |
| `DEBUG` | Enable debug mode | `False` |
| `DATA_DIR` | Directory for data storage | `/data` |
| `SECRET_KEY` | Key for session security and database encryption | Random value |
| `SYNCTHING_VERIFY_SSL` | Verify SSL certificates | `True` |

> **Important Security Note**: If you don't provide a `SECRET_KEY`, the application will generate a random one, but it will change on each restart. This will invalidate all existing sessions and could affect database access. For production use, ALWAYS set a consistent `SECRET_KEY` in your environment variables.

## Database Security

SyncAuth provides security through the following mechanisms:

- **Session Security**: The `SECRET_KEY` environment variable is used to sign session cookies
- **Data Storage**: Database is stored in SQLite within the specified `DATA_DIR`
- **Database Security**: The database uses SQLCipher for encryption when `SECRET_KEY` is provided
- **Authentication**: All authentication is performed via Syncthing instances

> **Note about `SECRET_KEY`**: If you don't provide a `SECRET_KEY`, the application will generate a random one, but it will change on each restart. For production use, always set a static `SECRET_KEY` in your environment variables to ensure consistent encryption.

> **CRITICAL WARNING**: The database is encrypted using the `SECRET_KEY` value. If you change, remove, or add a `SECRET_KEY` after initial setup, **your existing database will no longer work** and you'll lose access to all stored data. Always back up your database before changing the `SECRET_KEY`.

## User Interface

### Credential Synchronization

The credential synchronization page allows you to:

- **Manually sync credentials** to all enabled clients with a single click
- **Set up automatic synchronization** with the following schedule options:
  - Manual only (default)
  - Every hour
  - Once daily
  - Once weekly
  - Custom schedule with specific days and times
- **Configure quiet hours** when automatic syncs will not run
- **Enable browser notifications** for sync results

### Password Management

SyncAuth allows you to change Syncthing GUI passwords directly from the interface:

- **Change master password**: Update the password on the master Syncthing instance
- **Sync password changes**: Optionally propagate password changes to all enabled clients
- **Verify current password**: Security check to ensure the current password is valid

### Device Management

The unified device view provides:

- **Combined list** of both connected and managed devices
- **Enable/Disable sync** buttons for each device
- **Edit button** for modifying device configuration
- **Status indicators** showing connection status
- **IP/Domain display** showing device addresses in a clean format

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/setup` | GET, POST | Initial setup page to configure master Syncthing |
| `/login` | GET, POST | User login with Syncthing credentials |
| `/logout` | GET | User logout |

### Database Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/manage-encryption` | POST | Handle database encryption, decryption, reset actions |

### Configuration Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/master` | GET, PUT | Get or update master Syncthing configuration |
| `/api/clients` | GET, POST | List all clients or add a new client |
| `/api/clients/<client_id>` | GET, PUT, DELETE | Get, update, or delete a specific client |
| `/api/discover-devices` | GET | Discover devices from master Syncthing |
| `/api/connections` | GET | Get current connection status from master Syncthing |
| `/api/all-devices` | GET | Get unified list of all devices (connected and managed) |

### Synchronization Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sync-credentials` | POST | Synchronize credentials from master to clients |
| `/api/test-connection` | POST | Test connection to a client or master |
| `/api/test-stored-connection` | POST | Test connection using stored API key |
| `/api/check-config-changes` | GET | Check for config changes in Syncthing |
| `/api/change-password` | POST | Change Syncthing GUI password |

## Workflow

1. **Initial Setup**: Configure your master Syncthing instance
2. **Add Clients**: Either discover devices or add them manually
3. **Enable Sync**: For each device, enable synchronization
4. **Schedule Syncs**: Set up automatic synchronization schedule (optional)
5. **Set Credentials**: Change or update GUI credentials as needed
6. **Manage Passwords**: Update passwords directly from the interface

## Security Considerations

- API keys are stored in the SQLite database
- Database can be encrypted using SQLCipher for additional security
- Passwords are handled using bcrypt hashing
- All authentication is performed against the Syncthing instances
- Use HTTPS and proper network security for production deployments

## Troubleshooting

If you encounter synchronization issues:

1. Verify the API keys are correct
2. Ensure the Syncthing GUI is accessible at the provided address
3. Check for firewall rules that might be blocking communication
4. Look for TLS/SSL certificate issues if using HTTPS
5. Check the logs for detailed error messages

## Development

### Setup
1. Install dependencies for backend:
   ```
   pip install -r requirements.txt
   ```

2. Install dependencies for frontend:
   ```
   cd frontend
   yarn install
   ```

### Running in Development Mode
When developing, you can now run both the Flask backend and Quasar dev server with a single command:

```bash
python backend/app.py --dev
```

This will:
1. Start the Flask backend
2. Automatically launch the Quasar dev server
3. Forward all Quasar console output to your terminal
4. Handle API proxying automatically
5. Properly shut down both servers when you press Ctrl+C

The app will be available at http://localhost:9000

If you prefer to run them separately (for debugging or other purposes):

1. Start the Quasar dev server:
   ```
   cd frontend
   yarn quasar dev
   ```

2. In a separate terminal, start the Flask backend in dev mode:
   ```
   python backend/app.py --dev
   ```

### Building for Production

1. Build the Quasar SPA:
   ```
   cd frontend
   yarn build
   ```
   This will create production files in `frontend/dist/spa/`

2. Run the Flask application in production mode:
   ```
   python backend/app.py
   ```
   Without the `--dev` flag, Flask will serve the built static files from `frontend/dist/spa/`.

### Docker Compose (Recommended for Development)

Create a `docker-compose.yml` file:

```yaml
version: '3'
services:
  syncauth:
    build: .
    ports:
      - "5001:5001"
    volumes:
      - ./docker_data:/data
    env_file:
      - .env
    restart: unless-stopped
```

Create a secure `.env` file for your Docker Compose setup:
```bash
# Copy the example environment file
cp .env.example .env

# Generate a secure random key for production
NEW_KEY=$(openssl rand -hex 32)
echo "Generated key: $NEW_KEY"

# Manually edit .env to update the SECRET_KEY and other settings
# Or use one of these commands depending on your OS:
#
# For Linux:  sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
# For macOS:  sed -i '' "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
```

Then run:
```bash
docker-compose up -d
```

### Local Setup with pyenv

You can also use pyenv to create a dedicated Python environment for running SyncAuth without Docker.

#### macOS Setup

1. Install pyenv (if not already installed):
   ```bash
   brew update
   brew install pyenv
   ```

2. Add pyenv to your shell:
   ```bash
   echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
   echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
   echo 'eval "$(pyenv init -)"' >> ~/.zshrc
   ```

3. Restart your terminal or run `source ~/.zshrc`

4. Install Python and create a virtual environment:
   ```bash
   pyenv install 3.9.22
   pyenv local 3.9.22
   python -m venv venv
   source venv/bin/activate
   ```

5. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Note: The `pysqlcipher3` package might require additional system dependencies on macOS:
   ```bash
   brew install openssl sqlcipher
   export LDFLAGS="-L$(brew --prefix openssl)/lib -L$(brew --prefix sqlcipher)/lib"
   export CFLAGS="-I$(brew --prefix openssl)/include -I$(brew --prefix sqlcipher)/include"
   pip install pysqlcipher3==1.2.0
   ```

6. Set up environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Generate a secure random key
   NEW_KEY=$(openssl rand -hex 32)
   echo "Generated key: $NEW_KEY"
   
   # Manually edit .env to update the SECRET_KEY and other settings
   # For development, change these values:
   # DEBUG=false to DEBUG=true
   # HOST=0.0.0.0 to HOST=127.0.0.1
   #
   # Or use these commands:
   # sed -i '' "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
   # sed -i '' "s/^DEBUG=.*/DEBUG=true/" .env
   # sed -i '' "s/^HOST=.*/HOST=127.0.0.1/" .env
   ```

7. Run the application:
   ```bash
   python app.py
   ```

8. Access the web interface at `http://127.0.0.1:5001`

#### Linux Setup

1. Install pyenv dependencies and pyenv:
   ```bash
   sudo apt-get update
   sudo apt-get install -y make build-essential libssl-dev zlib1g-dev \
   libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
   libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev
   
   curl https://pyenv.run | bash
   ```

2. Add pyenv to your shell:
   ```bash
   echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
   echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
   echo 'eval "$(pyenv init -)"' >> ~/.bashrc
   ```

3. Restart your terminal or run `source ~/.bashrc`

4. Install Python and create a virtual environment:
   ```bash
   pyenv install 3.9.22
   pyenv local 3.9.22
   python -m venv venv
   source venv/bin/activate
   ```

5. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Note: The `pysqlcipher3` package might require additional system dependencies on Linux:
   ```bash
   sudo apt-get install -y libsqlcipher-dev
   pip install pysqlcipher3==1.2.0
   ```

6. Set up environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Generate a secure random key
   NEW_KEY=$(openssl rand -hex 32)
   echo "Generated key: $NEW_KEY"
   
   # Manually edit .env to update the SECRET_KEY and other settings
   # For development, change these values:
   # DEBUG=false to DEBUG=true
   # HOST=0.0.0.0 to HOST=127.0.0.1
   #
   # Or use these commands:
   # sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$NEW_KEY/" .env
   # sed -i "s/^DEBUG=.*/DEBUG=true/" .env
   # sed -i "s/^HOST=.*/HOST=127.0.0.1/" .env
   ```

7. Run the application:
   ```bash
   python app.py
   ```

8. Access the web interface at `http://127.0.0.1:5001`

## Technical Details

- **Backend**: Python Flask application
- **Frontend**: Alpine.js and Axios for a reactive UI
- **Storage**: SQLite database with optional SQLCipher encryption
- **Container**: Docker-based deployment
- **Persistence**: Volume mount for the database file
- **Authentication**: Uses Syncthing's own authentication mechanism

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).

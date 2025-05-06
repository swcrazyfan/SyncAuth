# SyncAuth - Syncthing Credential Synchronization Manager

SyncAuth is a containerized web application that allows you to synchronize Syncthing GUI credentials across multiple instances. It provides a clean web interface to manage your master and client Syncthing instances and automate the credential synchronization process.

## Features

- **Master-Client Configuration**: Configure a master Syncthing instance and manage multiple clients
- **Credential Synchronization**: Automatically sync GUI username and password across instances
- **Device Discovery**: Discover Syncthing devices from your master instance
- **Connection Testing**: Verify accessibility of all instances before synchronizing
- **Database Management**: Options to encrypt, decrypt, reset, or start over with your configuration database
- **Secure Storage**: Optionally encrypt your database with a secret key

## Requirements

- Docker
- Network access to all Syncthing instances
- API keys for all Syncthing instances

## Quick Start

### Build and Run with Docker

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/SyncAuth.git
   cd SyncAuth
   ```

2. Build the Docker image:
   ```
   docker build -t syncauth .
   ```

3. Run the container:
   ```
   docker run -d \
     --name syncauth \
     -p 5001:5001 \
     -v /path/to/data:/data \
     syncauth
   ```

   Optional: Set environment variables for configuration:
   ```
   docker run -d \
     --name syncauth \
     -p 5001:5001 \
     -v /path/to/data:/data \
     -e SECRET_KEY="your_encryption_key" \
     -e PORT=5001 \
     -e DEBUG=False \
     syncauth
   ```

4. Access the web interface at `http://localhost:5001`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Address to bind to | `0.0.0.0` |
| `PORT` | Port to listen on | `5001` |
| `DEBUG` | Enable debug mode | `False` |
| `DATA_DIR` | Directory for data storage | `/data` |
| `SECRET_KEY` | Encryption key for the database | Random value |

## Database Management

SyncAuth includes several database management options:

- **Encryption**: Encrypt your database using a secret key for enhanced security
- **Decryption**: Decrypt an existing encrypted database
- **Reset**: Reset the database while creating a backup of the existing data
- **Delete & Start Over**: Completely delete and recreate the database without backup

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

## Workflow

1. **Initial Setup**: Configure your master Syncthing instance
2. **Add Clients**: Either discover devices or add them manually
3. **Enable Sync**: For each device, enable synchronization
4. **Set Credentials**: Enter the desired GUI username and password
5. **Synchronize**: Apply the credentials to all enabled clients

## Security Considerations

- API keys are stored in the SQLite database
- Enable database encryption for sensitive environments
- All communication is done via the Syncthing API
- For production use, consider setting up HTTPS with a reverse proxy
- Only deploy in trusted networks where all Syncthing instances are reachable

## Troubleshooting

### Database Issues

If your database becomes corrupted or you forget your encryption key:
1. Use the "Delete & Start Over" option from the interface
2. Or delete the database file manually from your data volume
3. Restart the container

### Connection Issues

If you're having trouble connecting to Syncthing instances:
1. Verify the API keys are correct
2. Ensure the Syncthing GUI is accessible at the provided address
3. Check for firewall rules that might be blocking communication
4. Look for TLS/SSL certificate issues if using HTTPS

## Development

### Prerequisites

- Python 3.9+
- Flask and other dependencies listed in requirements.txt

### Local Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ```

## Technical Details

- **Backend**: Python Flask application
- **Frontend**: HTML, CSS, and vanilla JavaScript
- **Storage**: SQLite database with optional SQLCipher encryption
- **Container**: Docker-based deployment
- **Persistence**: Volume mount for the database file
- **Authentication**: Uses Syncthing's own authentication mechanism

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).

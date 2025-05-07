# SyncAuth - Product Requirements Document

## 1. Product Overview

SyncAuth is a containerized web application that enables users to synchronize Syncthing GUI credentials across multiple instances. It follows a master-client model where one Syncthing instance is configured as the master, and other instances are added as clients. The application provides a modern, responsive web interface built with Alpine.js and Axios for managing synchronization tasks.

### 1.1 Vision

To simplify Syncthing credential management across multiple instances, eliminating the need for manual configuration and ensuring consistent access across all nodes in a user's Syncthing network.

### 1.2 Goals

- **Simplify Management**: Reduce the complexity of maintaining consistent credentials across multiple Syncthing instances
- **Improve Security**: Ensure all instances are using the same strong credentials
- **Save Time**: Eliminate manual credential updates across multiple devices
- **Enhance Reliability**: Prevent access issues due to mismatched credentials

## 2. User Personas

### 2.1 Syncthing Power User

**Description**: Manages 5+ Syncthing instances across various devices (servers, desktops, mobile)  
**Pain Points**: Manually updating credentials on each instance is time-consuming and error-prone  
**Goals**: Simplify credential management, ensure consistent access across all devices  
**Technical Expertise**: High  

### 2.2 Small Business IT Administrator

**Description**: Maintains Syncthing for team file synchronization  
**Pain Points**: Need to ensure secure access for all team members  
**Goals**: Centrally manage credentials, simplify onboarding/offboarding processes  
**Technical Expertise**: Medium to High  

### 2.3 Home Server Enthusiast

**Description**: Runs Syncthing on home server and personal devices  
**Pain Points**: Occasionally forgets credentials for rarely-accessed instances  
**Goals**: Have consistent access to all synchronized data  
**Technical Expertise**: Medium  

## 3. Feature Requirements

### 3.1 Core Features

#### 3.1.1 Master-Client Configuration
- Configure a primary Syncthing instance as the master
- Add multiple Syncthing instances as clients
- Store connection details securely

#### 3.1.2 Credential Synchronization
- Synchronize GUI username and password across instances
- Support manual synchronization trigger
- Provide scheduled automatic synchronization
- Validate successful synchronization

#### 3.1.3 Device Management
- Discover Syncthing devices from master instance
- Add, edit, and remove client devices
- Enable/disable sync for individual devices
- Test connection to devices before synchronizing
- Display clean IP/domain information for all devices

#### 3.1.4 Password Management
- Change Syncthing GUI passwords directly from interface
- Option to propagate password changes to all clients
- Verify current password before allowing changes

#### 3.1.5 Synchronization Scheduling
- Support multiple scheduling options:
  - Manual only
  - Hourly
  - Daily
  - Weekly
  - Custom schedule (specific days/times)
- Configure quiet hours when automatic syncs will not run
- Enable browser notifications for sync results

### 3.2 Security Features

#### 3.2.1 Database Security
- Encrypt SQLite database using SQLCipher
- Support for encryption, decryption, and database reset
- Store API keys securely
- Require secret key for database access

#### 3.2.2 User Authentication
- Authenticate via Syncthing master instance
- Secure session management
- Session expiration for inactive sessions

### 3.3 Technical Requirements

#### 3.3.1 Performance
- Fast synchronization process (complete within 10 seconds for 10 clients)
- Responsive UI with minimal load times
- Low resource usage on host system

#### 3.3.2 Compatibility
- Support all Syncthing versions from v1.0.0 onwards
- Function with both HTTP and HTTPS Syncthing instances
- Support various network environments (local network, VPN, direct internet)

#### 3.3.3 Reliability
- Graceful handling of offline clients
- Retry mechanisms for failed connections
- Detailed error logging and reporting

### 3.4 Security Requirements

#### 3.4.1 Database Security
- SQLCipher encryption for database file
- API key encryption using Fernet with PBKDF2 key derivation
- SECRET_KEY environment variable required for encryption
- Clear UI indicators for database encryption status
- Backup mechanism before encryption/decryption operations

#### 3.4.2 Session Security
- CSRF protection for all forms
- Secure session cookies with HttpOnly and SameSite attributes
- Automatic session expiration
- Secure password hashing using bcrypt

### 3.5 Error Handling Requirements
- Comprehensive logging to file (/data/debug.log)
- Clear UI feedback for different error states
- Graceful handling of:
  - Database encryption/decryption failures
  - Syncthing API connection issues
  - Invalid user credentials

### 3.6 Database Management Workflows

#### 3.6.1 Initialization
1. Checks for existing database file
2. Validates database state (encrypted/unencrypted/corrupt)
3. Creates new database with tables if needed
4. Initializes API key encryption

#### 3.6.2 Encryption Process
1. Creates backup before encryption
2. Uses SQLCipher with provided SECRET_KEY
3. Handles encryption state transitions
4. Provides UI feedback throughout process

#### 3.6.3 API Key Security
1. Uses PBKDF2 with fixed salt for key derivation
2. Encrypts all API keys with Fernet
3. Stores encrypted keys in database
4. Decrypts only when needed

## 4. User Interface Requirements

### 4.1 General UI/UX
- Modern, responsive design (desktop and mobile)
- Intuitive navigation with clear labels
- Consistent visual language throughout
- Reactive interface using Alpine.js for real-time updates
- Optimized for touchscreens on mobile devices

### 4.2 Specific UI Components

#### 4.2.1 Dashboard
- Overview of master and client status
- Quick sync button
- Last sync status and timestamp
- Summary of enabled/disabled clients

#### 4.2.2 Device Management Interface
- Combined list of connected and managed devices
- Clear enable/disable sync options
- Edit button for modifying device configuration
- Status indicators showing connection status
- Display only IP/domain in address fields (not device names)

#### 4.2.3 Synchronization Schedule Interface
- Simple selector for schedule type
- Intuitive time/date pickers for custom schedules
- Clear display of next scheduled sync
- Toggle for enabling/disabling automatic sync

#### 4.2.4 Password Management Interface
- Secure password input fields
- Password strength indicator
- Clear confirmation for password changes
- Option toggle for propagating to clients

#### 4.2.5 Modal Dialogs
- Combined modal for collecting both address and API key
- Appropriate display when no address is available (e.g., "https://:8384")
- Consistent styling and behavior across all modals

### 4.3 Technical Stack

#### 4.3.1 Backend
- Python 3.9
- Flask web framework
- SQLite with SQLCipher for encrypted storage
- SQLAlchemy for database operations
- Flask-WTF for form handling and CSRF protection

#### 4.3.2 Frontend
- Alpine.js for reactivity and data binding
- Axios for API requests
- Modern CSS with responsive design

#### 4.3.3 Security
- pysqlcipher3 for database encryption
- cryptography library for API key encryption
- bcrypt for password hashing
- CSRF protection for all forms

### 4.4 Complete Authentication Flow

1. **Master Configuration**
   - Requires address and API key
   - Validates connection before saving
   - Stores encrypted API key

2. **User Login**
   - Verifies against master Syncthing instance
   - Uses bcrypt for password verification
   - Establishes secure session

3. **Session Management**
   - Secure cookies with HttpOnly/SameSite
   - Automatic session expiration
   - CSRF protection for all forms

## 5. API Requirements

### 5.1 Syncthing API Integration
- Support Syncthing REST API for all operations
- Handle API versioning differences across Syncthing versions
- Proper API key authentication
- Optional SSL certificate verification

### 5.2 Internal API Endpoints
- RESTful API design
- JSON response format
- Proper error status codes and messages
- Rate limiting for security

### 5.3 API Security
- All API endpoints require valid session authentication
- CSRF tokens required for state-changing operations
- Rate limiting on authentication endpoints
- Input validation on all API parameters

### 5.4 Complete Error Handling

#### 5.4.1 Database Errors
- Handles encryption/decryption failures
- Detects corrupt database states
- Provides recovery options

#### 5.4.2 Connection Errors
- Validates Syncthing API connections
- Handles SSL verification failures
- Provides detailed error messages

#### 5.4.3 Logging System
- Captures all stdout/stderr to debug.log
- Logs timestamps and severity levels
- Includes:
  - Authentication attempts
  - Database operations
  - API requests
  - System events

## 6. Storage and Data Requirements

### 6.1 Database
- SQLite with SQLCipher encryption
- Store master configuration
- Store client configurations
- Store synchronization history
- Store scheduling preferences

### 6.2 Data Security
- No plaintext storage of sensitive information
- Database encryption using user-provided secret key
- Option to reset database if key is lost

### 6.3 Logging Requirements
- Comprehensive logging to /data/debug.log
- Log rotation to prevent excessive disk usage
- Logging of:
  - Authentication attempts
  - Database operations
  - Synchronization events
  - Error conditions

## 7. Deployment Requirements

### 7.1 Docker Container
- Python 3.9 base image
- Include all dependencies
- Non-root user execution
- Volume mount for persistent data
- Environment variable configuration
- Proper signal handling for graceful shutdown

### 7.2 Environment Configuration
- Support for the following environment variables:
  - HOST
  - PORT
  - DEBUG
  - DATA_DIR
  - SECRET_KEY
  - SYNCTHING_VERIFY_SSL

## 8. Technical Architecture

### 8.1 Frontend
- HTML5 + CSS3
- Alpine.js for reactivity and data binding
- Axios for API requests
- Responsive design with mobile support

### 8.2 Backend
- Python with Flask web framework
- RESTful API design
- SQLite with SQLCipher for database
- Scheduler for automatic synchronization

### 8.2 Detailed Technical Architecture

#### 8.2.1 Authentication Flow
1. User must first configure master Syncthing instance
2. Subsequent logins verify against master instance
3. Sessions are established with secure cookies
4. All sensitive operations require re-authentication

#### 8.2.2 Database Encryption Flow
1. Application checks for SECRET_KEY at startup
2. Determines database encryption state
3. Provides UI options for encryption/decryption
4. Performs backup before encryption operations
5. Maintains clear status indicators

#### 8.2.3 Credential Synchronization Flow
1. User initiates sync from UI
2. System verifies master credentials
3. Connects to each client instance
4. Updates GUI credentials
5. Verifies successful update
6. Logs results

## 9. Security Considerations

### 9.1 Data in Transit
- Support for HTTPS connections to Syncthing instances
- Optional SSL verification
- Secure cookie handling

### 9.2 Data at Rest
- Encrypted database using SQLCipher
- No plaintext storage of API keys or passwords
- Secret key required for database access

### 9.3 Authentication
- Authentication via Syncthing credentials
- Session management with secure cookies
- Session timeout for inactive sessions

## 10. Success Metrics

### 10.1 Performance Metrics
- Synchronization completion time < 10 seconds for 10 clients
- UI response time < 500ms for all interactions
- Container resource usage < 100MB RAM at idle

### 10.2 User Metrics
- Time saved per credential change
- Number of successful synchronizations
- Number of automatically resolved credential mismatches

## 11. Testing Requirements

### 11.1 Functional Testing
- Verification of all core features
- Testing with various Syncthing versions
- Testing in different network environments

### 11.2 Security Testing
- Database encryption validation
- Session security testing
- API endpoint security testing

### 11.3 Compatibility Testing
- Multiple browsers (Chrome, Firefox, Safari, Edge)
- Mobile devices (iOS, Android)
- Various screen sizes and resolutions

## 12. Future Enhancements

### 12.1 Potential Future Features
- Support for additional Syncthing settings synchronization
- Webhook notifications for sync events
- Integration with monitoring systems
- Advanced scheduling with dependencies
- Multi-user access with role-based permissions

## 13. Implementation Status

### 13.1 Completed Features
- Master-client configuration (Flask endpoints, storage, Syncthing API integration).
- Credential encryption (SQLCipher for DB, Fernet for API keys).
- Client management UI (add/edit/delete, sync enable/disable).
- Manual and scheduled synchronization (Alpine.js scheduling engine, sync logic, browser notifications).
- Password management (change GUI password, propagate to clients).
- UI improvements (Alpine.js, Axios integration, modals, input sanitization).
- Error handling and logging (status messages, debug.log recording, CSRF protection).

### 13.2 In-Progress / Tweaks
- Schema versioning and database migration scripts.
- Salt rotation mechanism for API key encryption.
- Backup rotation and log rotation policies.
- Enhanced error recovery for corrupt or missing databases.
- Additional API endpoints (e.g., folder management, advanced device queries).
- Improved test coverage and integration in CI pipeline.

### 13.3 Next Steps
1. Implement schema versioning and migration framework.
2. Add dynamic salt generation and rotation for Fernet keys.
3. Enhance logging with rotation, retention, and alerting.
4. Develop comprehensive unit and end-to-end tests for all modules.
5. Refine UI scheduling interface and mobile responsiveness.
6. Integrate webhooks and monitoring for synchronization events.

## 14. Project Timeline

| Phase | Description | Duration |
|-------|-------------|----------|
| Research & Planning | Requirement gathering, technology selection | 2 weeks |
| Design | UI/UX design, architecture planning | 2 weeks |
| Implementation | Core functionality development | 4 weeks |
| Testing | Alpha testing, bug fixing | 2 weeks |
| Beta Release | Limited user testing | 2 weeks |
| Refinement | Addressing feedback, optimization | 2 weeks |
| Final Release | Production release | 1 week |
| Maintenance | Ongoing support and updates | Continuous |

## 15. Appendix

### 15.1 Glossary

- **Syncthing**: An open-source peer-to-peer file synchronization application
- **GUI Credentials**: Username and password used to access the Syncthing web interface
- **Master Instance**: The primary Syncthing instance that serves as the source of truth for credentials
- **Client Instance**: Any Syncthing instance that receives credentials from the master
- **API Key**: Authentication token used to access the Syncthing REST API
- **SQLCipher**: An extension to SQLite that provides transparent 256-bit AES encryption of database files

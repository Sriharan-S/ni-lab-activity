# Secure File Sharing Application Using HTTPS and Encryption

## Overview
This project implements a secure file-sharing application using Flask, AES encryption, JWT for authentication, and HTTPS for secure communication. The application ensures that files are encrypted before transmission and protects sensitive user data through secure communication channels.

## Features

- **User Authentication**: User registration and login with password hashing using bcrypt, and token-based authentication using JWT.
- **File Encryption**: Files are encrypted using AES encryption (CBC mode) before being uploaded.
- **File Decryption**: Encrypted files are decrypted before being downloaded.
- **Secure Communication**: The application uses HTTPS for secure communication.
- **JWT Authentication**: JWT tokens are used to authenticate users for file uploads and downloads.

## Technologies Used

- **Flask**: A Python micro web framework for building the application.
- **PyCryptodome**: A Python library for implementing AES encryption.
- **JWT (JSON Web Tokens)**: A method for securely transmitting information for user authentication.
- **SQLite**: A lightweight database used to store user data and file metadata.
- **Bcrypt**: A hashing algorithm used to securely hash user passwords.
- **HTTPS**: Secure communication protocol for encrypted data transfer.

## Prerequisites

To run this application, you need the following installed:

- Python 3.6 or higher
- Flask
- PyCryptodome
- Bcrypt
- SQLite
- SSL certificates (for HTTPS)

You can install the required Python libraries by running:

```bash
pip install flask pycryptodome bcrypt pyjwt
```

## Running the Application

1. **Clone the Repository**:
   Clone the project repository to your local machine.

   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. **Set Up the Database**:
   The application uses SQLite as its database. Run the following command to set up the database:

   ```bash
   python app.py
   ```

3. **Running the Application**:
   To start the Flask application, use the following command:

   ```bash
   python app.py
   ```

   The server will start and run on `https://127.0.0.1:5000/` by default (with HTTPS enabled).

   **Note**: For production, you'll need to configure SSL certificates and set up a proper web server like Nginx or Apache to serve the Flask app.

## API Endpoints

### 1. **User Registration** (`POST /register`)

Register a new user by providing a username and password.

**Request Body**:
```json
{
  "username": "user1",
  "password": "password123"
}
```

**Response**:
```json
{
  "message": "User registered successfully"
}
```

### 2. **User Login** (`POST /login`)

Login with the username and password to receive a JWT token.

**Request Body**:
```json
{
  "username": "user1",
  "password": "password123"
}
```

**Response**:
```json
{
  "token": "<JWT_token>"
}
```

### 3. **File Upload** (`POST /upload`)

Upload a file. The file will be encrypted before storing it in the database.

**Headers**:
- Authorization: Bearer `<JWT_token>`

**Request Body**:  
Use the `file` field to upload the file.

**Response**:
```json
{
  "message": "File uploaded successfully"
}
```

### 4. **File Download** (`GET /download/<filename>`)

Download an encrypted file. The file will be decrypted before being sent to the client.

**Headers**:
- Authorization: Bearer `<JWT_token>`

**Response**:  
The requested file will be returned as an attachment for download.

If the file is not found, the following message will be returned:
```json
{
  "message": "File not found"
}
```

## Security Considerations

- **HTTPS**: This application uses HTTPS to encrypt data transmitted between the client and the server.
- **Encryption**: Files are encrypted using AES (Advanced Encryption Standard) with CBC (Cipher Block Chaining) mode before they are uploaded, ensuring that even if someone intercepts the files, they cannot read them.
- **JWT Authentication**: Users are authenticated using JWT tokens, ensuring that only authorized users can upload or download files.

## Troubleshooting

1. **HTTPS Not Working**:
   - Ensure you have SSL certificates properly set up for production use. For local testing, Flask's built-in SSL context can be used (`ssl_context='adhoc'`).

2. **File Not Found**:
   - Ensure the file exists in the database by checking the filename.

3. **Token Expired**:
   - JWT tokens are valid only for a limited period. If you encounter this error, log in again to receive a new token.

## Conclusion

This application provides a secure way to share files over the internet by encrypting files before transmission and using HTTPS for secure communication. The use of JWT tokens ensures that only authenticated users can upload or download files, while AES encryption protects sensitive data during storage and transmission.

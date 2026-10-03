# ConnectChat

WhatsApp-style real-time chat starter for GitHub + Render.

Features:
- User registration/login
- Own profile name, bio and profile picture
- Real-time one-to-one text chat
- Image/file sending
- Groups
- Live rooms
- Admin dashboard
- Admin can inspect users, messages and files
- Passwords are bcrypt hashes and are NEVER shown as plaintext

## Render deployment

1. Create a GitHub repository and upload all files in this project.
2. In Render create a PostgreSQL database.
3. Create a Render Web Service from the GitHub repository.
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Link the PostgreSQL database to the web service so `DATABASE_URL` is available.
7. Add:
   - `JWT_SECRET` = long random secret
   - `ADMIN_EMAIL` = your admin email
   - `ADMIN_PASSWORD` = strong admin password
   - `MAX_FILE_MB` = `15`
8. Deploy.
9. Open the site and log in with the admin account.

The server creates the PostgreSQL tables automatically.

## Storage note

This version stores uploaded files in PostgreSQL so they survive normal Render restarts. It is suitable for a prototype/small deployment. For a large public service, move binary files to object storage and keep metadata in PostgreSQL.

## Security note

The admin can inspect messages/files because this is an admin-controlled platform. Passwords are deliberately not readable by anyone, including the admin. The admin can reset a password in a future version.

Before a large public launch, add rate limiting, email verification, malware scanning, backups, abuse reporting and stronger production security controls.

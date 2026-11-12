# RTB TOP UP — Server-backed Admin Starter

This is a real backend-backed admin starter, not a standalone HTML mockup. It includes:
- Admin login with bcrypt password hash
- HttpOnly, SameSite=Strict session cookie; hashed session tokens stored in SQLite
- Login rate limiting and basic security headers
- SQLite persistent data for packages, offers, orders and site settings
- Admin CRUD for packages and offers; order status updates
- Public active catalogue endpoint at `/api/catalog`

## Important limitations
This is **not yet a complete live top-up store**. It does not include Google/Facebook customer auth, customer registration/profile, public order submission UI, payment gateway, supplier/top-up API, automated delivery, refunds, or payment reconciliation. Do not collect customer payments until these are integrated and tested. Keep customer data minimal and use a trusted adult's help for hosting/payment accounts.

## Run locally
Requires Node.js 20+.
1. Copy `.env.example` to `.env`.
2. Set `ADMIN_USERNAME` to your chosen username.
3. Create a bcrypt hash for a strong, unique password:
   ```bash
   node -e "const b=require('bcryptjs'); console.log(b.hashSync(process.argv[1],12))" "YOUR-STRONG-PASSWORD"
   ```
   Put the output in `ADMIN_PASSWORD_HASH`.
4. Set `SESSION_SECRET` to a random string of at least 32 characters.
5. Install and run:
   ```bash
   npm install
   npm start
   ```
6. Open `http://localhost:3000`.

## Deploy
The included `render.yaml` is a starting point for Render. Create a new Web Service from this project and configure:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD_HASH`
- `SESSION_SECRET` (use a unique random secret)
- Persistent disk mounted at `/var/data` (the blueprint requests this)
Do not commit `.env` or secrets to Git. Use HTTPS in production. Review the hosting provider's current pricing and persistent-disk requirements before deploying.

## Data notes
The database file is stored at `DATABASE_PATH`. Back it up securely. Admin sessions expire after 8 hours. Change the admin password by generating a new bcrypt hash and updating the environment variable, then restart the service; revoke existing sessions by clearing the `sessions` table if required.

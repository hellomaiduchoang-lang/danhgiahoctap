# ClassTrack

ClassTrack is a Vietnamese class-management workspace. The current implementation is Phase 1: a same-origin Node.js/Express API and PostgreSQL persistence for authentication, class membership, class-scoped roles and permissions, role requests, and conduct records. The existing conduct dashboard now reads and writes server data. Learning content, assignments, exams, document library, forum, and notifications remain for later phases. It does not include live classrooms, livestreams, voice/video calls, or live exams.

## Local setup on Windows

Run these commands in PowerShell from the project directory. They bypass the script policy for this process only; they do not change the machine-wide policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-local.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-local.ps1
```

Setup downloads and checksum-verifies the official Node.js 24 and PostgreSQL 18 portable distributions into your Windows user profile (no administrator rights required), initializes a local PostgreSQL data directory, creates the application database, installs API packages, applies migrations, and seeds the sample class. Generated database and teacher credentials are saved to the ignored `api/.env`; setup prints the teacher login once when it completes. Start the website with `start-local.ps1` and open the exact local address printed by the script. It uses the configured local port consistently and detects if another server is occupying that port instead of silently starting on a different address. Press `Ctrl+C` in the startup window to stop the website. Do not open `index.html` directly as a file; the API must be running through the local server.

The local start script checks that PostgreSQL is accepting connections, not just that its process exists. If PostgreSQL is stuck in a non-responsive state, the script attempts a clean restart before starting or reusing the API.

If you already installed Node.js and PostgreSQL yourself, use the manual configuration and commands below instead.

## Publishing and deployment

Pushing this repository to Git stores the source code; it does not run the website. GitHub Pages cannot run this project's Node.js API or PostgreSQL database, so the login and data features will return 404 if only `index.html` is published there.

### Deploy from GitHub with Render

The root `render.yaml` defines a paid Node.js web service and PostgreSQL database. It runs API commands from `api/` while keeping the repository root available so the server can also serve `index.html` from the same origin, which is required for login cookies. Review Render's current pricing before deploying; the Blueprint creates billable resources.

1. Push the repository to GitHub.
2. In Render, choose **New > Blueprint**, connect the repository, and select the branch to deploy. Review the paid web and database resources before confirming.
3. Wait for the first deployment to finish, then open the service URL shown by Render. Do not use the GitHub Pages URL for the working app.
4. In the paid Render service's **Shell**, run this from the directory containing `api/package.json` (if the shell starts at the repository root, first run `cd api`) to create the first administrator:

   ```sh
   ADMIN_USERNAME=admin ADMIN_FULL_NAME="ClassTrack Admin" ADMIN_PASSWORD='use-a-unique-long-password' npm run db:create-super-admin
   ```

   Replace the example password with a unique secret. Do not put it in `render.yaml`, GitHub, or source files. The script refuses to create a second Super Admin.
5. Sign in at the Render service URL. The service runs database migrations on startup and `/api/health` is used as its health check.

Keep GitHub Pages disabled for this app, or use it only for static documentation. A `github.io` URL cannot host the Node API or PostgreSQL database.

### Other Node.js hosts

Deploy the whole project to a Node.js host with a PostgreSQL database, and serve the page and `/api/*` routes from the same origin. Configure the service with `api` as its working directory, `npm ci` as its install command, and `npm run db:migrate && npm start` as its start command. The server uses the host-provided `PORT` and listens on the public container interface in production.

Set these environment variables in the hosting provider's secret/configuration panel:

- `NODE_ENV=production`
- `DATABASE_URL` to the managed PostgreSQL connection string
- `APP_ORIGIN` to the exact public HTTPS origin, such as `https://classtrack.example.com` (Render's `RENDER_EXTERNAL_URL` is also supported)

The frontend must share the API's public origin in production. Setting `FRONTEND_ORIGIN` only permits browser requests at the API; this static frontend does not support configuring a different production API URL, and its `SameSite=Strict` session cookie is not suitable for a cross-site frontend. If the frontend is hosted separately, put a same-origin reverse proxy in front of the API and frontend. In development, frontend pages served from any HTTP port on `localhost` or `127.0.0.1` are allowed with credentialed CORS.

After the first deployment has applied migrations, create the initial administrator once from the service shell in the `api` directory. Set `ADMIN_USERNAME`, `ADMIN_FULL_NAME`, and a unique `ADMIN_PASSWORD` of 12–72 UTF-8 bytes as temporary environment secrets, then run `npm run db:create-super-admin`. Remove the temporary password secret afterward. This command refuses to run if a Super Admin already exists. Do not use `npm run db:seed` for a real deployment; it creates demo class data. Never commit `.env`, database credentials, or administrator passwords to Git.

### Manual setup

Requirements: Node.js 20 or later and PostgreSQL 14 or later.

1. Create a PostgreSQL database and a dedicated application user.
2. In PowerShell, copy `api/.env.example` to `api/.env`; set `DATABASE_URL`, `APP_ORIGIN`, `BOOTSTRAP_TEACHER_USERNAME`, and a unique bootstrap password of at least 12 characters. Do not use the example password outside local development.
3. Install and initialize:

   ```powershell
   Set-Location api
   npm install
   npm run db:migrate
   npm run db:seed
   npm start
   ```

4. Open `http://localhost:3000` and sign in with the bootstrap teacher username and password configured in `api/.env`.

The seed command creates the demo class `10A1`, its sample students and conduct records, and the configured administrator-teacher account. The first existing administrator is the initial Super Admin; Super Admins can create ordinary admins and grant their limited admin permissions. Admins with account-management permission can search and filter accounts, lock or unlock accounts, revoke sessions, and issue a temporary password that expires after 24 hours and must be changed at next sign-in. Sensitive admin actions are audited. Administrators create teacher accounts; only teachers can create student accounts. Teachers enter student names (one name per line), and ClassTrack generates a unique student number, username, and random password for each account. Credentials download as an Excel-compatible UTF-8 CSV file. Users cannot self-register or assign themselves privileged roles. The interface supports light and dark themes.

## Database and access control

Migrations in `api/db/migrations` are additive and tracked in `schema_migrations`. Phase 1 includes users, classes, class memberships with multiple roles per class, groups, permissions, role requests, conduct records, evidence metadata, auth sessions, and audit logs. Each class-scoped API checks the authenticated user's active membership and effective permissions on the server. Students receive only their own conduct records; group leaders receive records for their groups; teacher access is class-scoped.

`api/src/server.js` serves this page and the API from the same origin. The server stores only a hash of each opaque session token; cookies are HttpOnly and SameSite=Strict. Mutating requests require the configured `APP_ORIGIN`. Set `NODE_ENV=production`, use HTTPS, and use a properly managed database secret before deployment.

Role-request APIs are `POST /api/classes/:classId/role-requests`, `GET /api/classes/:classId/role-requests`, and teacher-only `PATCH /api/classes/:classId/role-requests/:requestId`. Teachers manage additional per-member permissions through `PUT /api/classes/:classId/members/:memberId/permissions`. These actions are audited; role approvals and permission grants are checked against class membership on the server.

## Existing browser data

The prior prototype stored changes separately in each browser's `localStorage`, which cannot be safely merged into a shared database without identifying the class, student, and recorder. The new interface uses PostgreSQL and does not modify those browser keys. The seed restores the original sample class data; records created in a browser before this upgrade remain in that browser's local storage and need a separate, reviewed import if they must be retained.

Evidence uploads are not implemented in Phase 1. Conduct entries retain the selected filename only; the file bytes are not uploaded or stored.

## Verification

```powershell
Set-Location api
$env:PATH = "$env:LOCALAPPDATA\ClassTrack\runtime\node-v24.22.1-win-x64;$env:PATH"
npm test
```

The PATH step is needed when using the portable Windows setup; omit it if Node.js is already on your PATH. The API requires a reachable PostgreSQL database for migration, seeding, and runtime checks.

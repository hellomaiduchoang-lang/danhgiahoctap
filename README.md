# ClassTrack

ClassTrack is a Vietnamese class-management workspace. The root Express server serves `public/index.html` and implements database-backed authentication using the shared PostgreSQL schema in `api/db/migrations`. A fuller ClassTrack API remains under `api/`.

## Minimal root server

The root `package.json` is the entry point used by `render.yaml`. It serves the existing `public/index.html`, provides `GET /health`, and supports `POST /api/auth/login`, `GET /api/session`, and `POST /api/auth/logout`. Login uses the frontend's `username` and `password` fields, bcrypt password hashes, PostgreSQL-backed opaque sessions, and an HttpOnly cookie. Other unimplemented API endpoints return HTTP 501 with `NOT_IMPLEMENTED`.

Run locally from the repository root:

```sh
npm install
npm run db:migrate
npm run db:seed
npm start
```

Set `DATABASE_URL`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` in the environment before running the migration and seed commands. The seed creates the initial Super Admin account and requires a password of 12–72 UTF-8 bytes. `db:migrate` applies the existing SQL migration set under `api/db/migrations`; `db:seed` can be rerun for the already-seeded Super Admin and refuses to create a second one. The frontend also calls APIs for classes and students, conduct records and categories, forums, weekly scores, role requests, leadership and groups, account settings, and administration. Those routes still return `NOT_IMPLEMENTED`.

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

Pushing this repository to Git stores the source code; it does not run the website. Deploy the Node.js API, PostgreSQL database, and static frontend together as one Render Web Service so the browser and API share an origin.

### Deploy from GitHub with Render

The root `render.yaml` defines a paid Node.js web service and PostgreSQL database in the same region. The web service installs the root package, applies database migrations before each deploy, starts with `npm start`, and checks `/health`. Review Render's current pricing before deploying; the Blueprint creates billable resources.

1. Push the repository to GitHub.
2. In Render, choose **New > Blueprint**, connect the repository, and select the branch to deploy. Review the paid web and database resources before confirming.
3. Configure `ADMIN_USERNAME` and `ADMIN_PASSWORD` as Render environment secrets. Use a unique password of 12–72 UTF-8 bytes.
4. Wait for the deployment to finish. Open the Render service URL. Confirm `/health` returns `{"ok":true}` and `/` serves the page. Run `npm run db:seed` once from the Render Shell to create the initial Super Admin.
5. To deploy the fuller PostgreSQL-backed implementation in `api/` instead, configure the Render service root directory as `api`, install with `npm install`, run `npm run db:migrate` as a pre-deploy step, and use `npm start`. Do not switch a service with existing production data without first reviewing its deployment settings and database.

For the `api/` implementation, run its production administrator seed from the service root directory (`api`) after migrations:

```sh
npm run db:seed:admin
```

Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` as private environment variables. This command creates the Super Admin when absent and updates the password when the username already exists, so rerunning it resets that account's password. Do not put credentials in GitHub or source files. Do not run `npm run db:seed` against a production database; it inserts demo class data.

### Other Node.js hosts

Deploy the whole repository to a Node.js host with a PostgreSQL database, and serve `public/index.html` and `/api/*` from the same origin. Install dependencies with `npm --prefix api ci`, run `npm --prefix api run db:migrate` as a pre-deploy step, and start with `npm --prefix api start`. The server uses the host-provided `PORT` and listens on `0.0.0.0`.

Set these environment variables in the hosting provider's secret/configuration panel:

- `NODE_ENV=production`
- `DATABASE_URL` to the managed PostgreSQL connection string
- `APP_ORIGIN` to the exact public HTTPS origin if the host does not provide `RENDER_EXTERNAL_URL`
- `PORT` is assigned by Render; do not hard-code it in Render settings

The Blueprint generates a `SESSION_SECRET` environment value, but the current session implementation uses random opaque tokens whose hashes are stored in PostgreSQL and does not read that variable. Production cookies are HttpOnly, Secure, and SameSite=Lax. CORS is not needed for this same-origin setup; the API does not allow wildcard origins.

After the first deployment has applied migrations, run `npm run db:seed:admin` in the service root directory (`api`) with `ADMIN_USERNAME` and a unique `ADMIN_PASSWORD` of 12–72 UTF-8 bytes set in the hosting provider's environment settings. Rerunning the command updates that account's password. Never run `npm run db:seed` on a real deployment; it creates demo class data. Never commit `.env`, database credentials, or administrator passwords to Git.

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

`api/src/server.js` serves `public/index.html` and the API from the same origin. The server stores only a hash of each opaque session token; production cookies are HttpOnly, Secure, and SameSite=Lax. Mutating requests require an allowed origin. Set `NODE_ENV=production`, use HTTPS, and use a properly managed database secret before deployment.

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

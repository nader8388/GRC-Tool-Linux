# GRC Assessment Platform — Server

Self-hosted, multi-user web server for compliance assessments across ISO 27001, NIST 800-53, SOC 2, PCI DSS, and more.

---

## Quick Start

### Option 1 — npx (no install required)

```bash
npx grc-assessment-server
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.  
Data is stored in `./data/` and uploads in `./uploads/` in your current directory.

### Option 2 — Global install

```bash
npm install -g grc-assessment-server
grc-assessment-server
```

### Option 3 — Docker Compose (recommended for production)

```bash
# 1. Copy the environment file and set a secure secret
cp .env.example .env
# Edit .env and set SESSION_SECRET to a random string:
#   openssl rand -hex 32

# 2. Start the server
docker compose up -d

# 3. Open in browser
open http://localhost:3000
```

### Option 4 — Docker only

```bash
docker run -d \
  --name grc-assessment \
  -p 3000:3000 \
  -v grc_data:/app/data \
  -v grc_uploads:/app/uploads \
  -e SESSION_SECRET=change_this_to_a_random_secret \
  grc-assessment-server
```

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Port the server listens on |
| `SESSION_SECRET` | *(required in production)* | Secret used to sign session cookies — use a long random string |
| `NODE_ENV` | `development` | Set to `production` in production |
| `GRC_DATA_DIR` | `./data` | Directory for SQLite database files |
| `GRC_UPLOADS_DIR` | `./uploads` | Directory for file attachments |

> ⚠️ **Always set a strong `SESSION_SECRET` in production.**  
> Generate one with: `openssl rand -hex 32`

---

## First Run

On first launch, navigate to the server URL and you will be prompted to create an admin account. No pre-configuration needed.

---

## Publishing a new Docker image

```bash
docker build -t grc-assessment-server .
docker tag grc-assessment-server your-dockerhub-username/grc-assessment-server:latest
docker push your-dockerhub-username/grc-assessment-server:latest
```

## Publishing to npm

```bash
npm login
npm publish
```

---

## Data Persistence

- **SQLite database** — stored in `data/grc.db`
- **File attachments** — stored in `uploads/`

When using Docker, both are mounted as named volumes (`grc_data`, `grc_uploads`) so they survive container restarts and updates.

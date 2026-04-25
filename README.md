# GRC Assessment Platform — Linux Server Edition

Multi-user web server version. Users access via browser — no installation required.

## Quick Start (Docker)

```bash
# 1. Clone / copy files to your server
# 2. Set a secure session secret
export SESSION_SECRET="$(openssl rand -hex 32)"

# 3. Build and start
docker compose up -d

# 4. Open http://your-server-ip:3000 in a browser
# 5. Create the first admin account on first visit
```

## Manual Install (without Docker)

```bash
# Requirements: Node.js 18+, npm
npm install --production
node server.js
```

Environment variables:
- `PORT` — port to listen on (default: 3000)
- `SESSION_SECRET` — secret key for sessions (CHANGE IN PRODUCTION)
- `NODE_ENV` — set to `production` for production deployments

## With Nginx + HTTPS (recommended for production)

1. Install certbot and get an SSL certificate:
```bash
sudo certbot certonly --standalone -d your-domain.com
```

2. Copy `nginx.conf` to `/etc/nginx/sites-available/grc` and edit `your-domain.com`

3. Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/grc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

4. Update `docker-compose.yml` to only expose on localhost:
```yaml
ports:
  - "127.0.0.1:3000:3000"
```

## Data Persistence

All data is stored in the `data/` directory:
- `data/grc.db` — SQLite database (users, assessments, audit log)
- `data/sessions.db` — session store
- `uploads/` — file attachments

**Back up these directories regularly.**

With Docker, data is stored in named volumes (`grc_data`, `grc_uploads`).
To back up: `docker run --rm -v grc_data:/data -v $(pwd):/backup alpine tar czf /backup/grc-backup.tar.gz /data`

## User Roles

| Role | Capabilities |
|---|---|
| Admin | Full access, manage users, enable/disable standards, reset data |
| Assessor | Assess controls, view audit log |
| Viewer | Read-only access |

## Upgrading

```bash
docker compose pull
docker compose up -d
```

Data is preserved in named volumes across upgrades.

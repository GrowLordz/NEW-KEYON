# FORGE/OS Online Key Backend

Architecture: VIP.lua -> Vercel API -> Supabase PostgreSQL.

## Supabase
1. Create a project.
2. Open SQL Editor.
3. Run `supabase/schema.sql`.
4. Copy Project URL and a server-side secret key.

## Vercel environment variables
Add these under Project Settings -> Environment Variables:

SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SECRET_KEY=YOUR_SUPABASE_SECRET_KEY
PANEL_ADMIN_TOKEN=make-a-long-random-token

Do NOT put SUPABASE_SECRET_KEY in index.html or VIP.lua.

## Deploy
Upload this folder to Vercel or connect a Git repository, then deploy.

Test:
GET /api/health

Admin list:
GET /api/keys with Authorization: Bearer PANEL_ADMIN_TOKEN

Create key:
POST /api/keys
Authorization: Bearer PANEL_ADMIN_TOKEN
Content-Type: application/json
{"action":"create","key":"GROW-20260829-AAAA-BBBB-1234","owner":"test","days":30}

Check from VIP.lua:
POST /api/check-key
Content-Type: application/json
{"key":"GROW-20260829-AAAA-BBBB-1234","uid":"12345"}

IMPORTANT: The current index.html is still the original localStorage panel. The API is ready, but the panel must be migrated from localStorage to these endpoints before it is the final online dashboard.

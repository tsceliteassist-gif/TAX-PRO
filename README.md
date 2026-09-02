# TSC Elite Tax Service Bureau

GitHub-first, Lovable-compatible web application for TSC Elite Assist Tax Pro LLC.

## Included

- Public website for tax clients and tax professionals
- Preparer application and client registration
- Supabase email/password authentication
- Role-aware portals for Owner/Admin, Tax Preparer, Tax Client and Support Staff
- Secure tax cases, appointments, messages, tickets and private document storage
- Row Level Security policies preventing cross-account access
- Skool Tax Academy and Calendly connections through environment variables

## Local setup

1. Copy `.env.example` to `.env` and add the Supabase project values.
2. Run the SQL migration through the Supabase CLI or SQL editor.
3. Replace `VITE_SKOOL_COMMUNITY_URL` with the private community URL.
4. Run `npm install` and `npm run dev`.

## Security rules

- New signups always begin as pending tax clients. A browser request can never grant itself staff, preparer or owner privileges.
- Only a database administrator can bootstrap the first Owner/Admin.
- Owner/Admin may approve applications and promote roles.
- Clients only see their own cases; preparers only see assigned cases; support access is operational; owner access is global.
- Tax documents use a private bucket and case-ID folder paths.
- Never commit `.env`, API secrets, service-role keys, taxpayer SSNs or production documents.

## Lovable workflow

Connect the GitHub repository inside Lovable. Make changes in GitHub/Codex and let Lovable sync the branch; reserve Lovable prompts for preview or platform-specific work.

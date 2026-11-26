# Sistema Whats — KNJ

Initial foundation, not production-ready. Node 22, TypeScript, React, PostgreSQL, Evolution API, Coolify. Run npm install, npm run build, npm start. Docker builds the app. Set DATABASE_URL (TLS verified), BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD and BOOTSTRAP_COMPANY for initial setup; remove bootstrap secrets after first start. HTTPS required. No public registration. Modules beyond contacts are schema/navigation foundations only. Evolution adapter is not wired to sending or webhooks. Rotate shared database credentials. Use a dedicated non-superuser database role without BYPASSRLS. Validate in staging before production.

## Evolution global
Set EVOLUTION_API_KEY to the global server key, EVOLUTION_URL, PUBLIC_APP_URL (HTTPS), and EVOLUTION_WEBHOOK_SECRET. Create a new tenant instance in Enviar, then link via QR. Existing external instances are not deleted. Old local history is retained.

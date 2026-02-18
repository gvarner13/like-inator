# Hono Migration Plan (Routes + WebSockets)

Goal: migrate from a plain Worker handler to Hono while preserving existing route and WebSocket behavior, with one commit per step.

## Branch

- Branch: `feature-hono-migration`

## Commit Steps

1. **docs: add hono migration execution plan**
- Add this `plan.md` file as the migration checklist.

2. **chore: add hono and scaffold cloudflare app entrypoint**
- Add `hono` as a direct dependency.
- Convert `src/index.ts` to a Hono app entrypoint (`export default app`).
- Add `app.notFound(...)` and `app.onError(...)` to preserve API-style error responses.

3. **feat: wire agent websocket routing through hono**
- Route `/agents/*` through `routeAgentRequest(c.req.raw, c.env)`.
- Preserve WebSocket upgrade behavior for `/agents/research-agent/{name}`.

4. **feat: migrate research routes to hono**
- Migrate `POST /research`.
- Migrate `GET /status` as GET-only behavior.
- Preserve response payloads and validation behavior.

5. **feat: migrate x oauth routes to hono**
- Migrate `GET /auth/x/login` and `GET /auth/x/callback`.
- Preserve PKCE cookies, redirect behavior, token exchange/storage.

6. **feat: migrate liked-posts routes to hono**
- Migrate `GET /x/liked-posts` and `GET /x/liked-posts/websites`.
- Preserve token fallback, cache behavior, pagination/rate-limit handling.

7. **test: validate hono route parity and status method behavior**
- Keep existing test expectations for `/`, OAuth, and liked-posts auth failure.
- Add method behavior test for `/status` non-GET.

8. **chore: finalize hono migration verification**
- Run test suite and confirm behavior manually where needed.
- Keep this commit focused on verification-only deltas.

## Route Parity Checklist

- `POST /research`
- `GET /status`
- `GET /auth/x/login`
- `GET /auth/x/callback`
- `GET /x/liked-posts`
- `GET /x/liked-posts/websites`
- `GET /`
- WebSocket: `/agents/research-agent/{name}` via `routeAgentRequest`

## Notes

- Maintain existing helper logic in `src/index.ts` unless required for Hono routing.
- Run `wrangler types` if bindings change in `wrangler.jsonc`.

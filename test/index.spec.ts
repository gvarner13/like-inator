import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('Hello World worker', () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('responds with Hello World! (unit style)', async () => {
		const request = new IncomingRequest('http://example.com');
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		expect(await response.text()).toMatchInlineSnapshot(`"Hello World!"`);
	});

	it('responds with Hello World! (integration style)', async () => {
		const response = await SELF.fetch('https://example.com');
		expect(await response.text()).toMatchInlineSnapshot(`"Hello World!"`);
	});

	it('redirects to X OAuth authorize URL with PKCE and state', async () => {
		const authEnv = {
			...(env as unknown as Record<string, string>),
			CLIENT_ID: 'test-client-id',
			X_OAUTH_REDIRECT_URI: 'http://example.com/auth/x/callback',
			X_OAUTH_SCOPES: 'tweet.read users.read like.read offline.access',
		} as unknown as Env;

		const request = new IncomingRequest('http://example.com/auth/x/login');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(302);
		const location = response.headers.get('Location');
		const cookie = response.headers.get('Set-Cookie');

		expect(location).toContain('https://x.com/i/oauth2/authorize');
		expect(location).toContain('code_challenge_method=S256');
		expect(location).toContain('client_id=test-client-id');
		expect(cookie).toContain('x_oauth_pkce=');
		expect(cookie).toContain('HttpOnly');
	});

	it('rejects callback when required oauth params are missing', async () => {
		const callbackRequest = new IncomingRequest('http://example.com/auth/x/callback');
		const callbackCtx = createExecutionContext();
		const callbackResponse = await worker.fetch(callbackRequest, env, callbackCtx);
		await waitOnExecutionContext(callbackCtx);

		expect(callbackResponse.status).toBe(400);
		const body = (await callbackResponse.json()) as { error: string };
		expect(body.error).toBe('missing_oauth_parameters');
	});

	it('rejects liked posts request without bearer token', async () => {
		const request = new IncomingRequest('http://example.com/x/liked-posts');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
		const body = (await response.json()) as { error: string };
		expect(body.error).toBe('missing_access_token');
	});
});

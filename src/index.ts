import { Client, OAuth2, generateCodeChallenge, generateCodeVerifier, type OAuth2Config } from '@xdevplatform/xdk';
import { getAgentByName, routeAgentRequest } from 'agents';
import { Hono } from 'hono';

export { ResearchAgent } from './agent';
export { ResearchWorkflow } from './workflow';

const PKCE_COOKIE = 'x_oauth_pkce';
const PKCE_TTL_SECONDS = 10 * 60;
const X_TOKENS_KV_KEY = 'x:oauth:single-user:tokens';
const ACCESS_TOKEN_REFRESH_BUFFER_SECONDS = 60;
const X_LIKED_POSTS_RATE_LIMIT_WINDOW_MINUTES = 15;
const X_LIKED_POSTS_CACHE_KEY_PREFIX = 'x:liked-posts:cache';
const DEFAULT_X_USER_ID = '14446479';
const DEFAULT_SCOPES = ['tweet.read', 'users.read', 'like.read', 'offline.access'];
const DEFAULT_LIKED_POSTS_PER_PAGE = 25;
const MAX_LIKED_POSTS_PER_PAGE = 100;

type EnvMap = Record<string, string | undefined>;
type StoredXTokens = {
	accessToken: string;
	refreshToken: string | null;
	tokenType: string;
	scope: string | null;
	expiresAt: number | null;
	userId: string | null;
	updatedAt: number;
};

type LikedPostsResponseBody = {
	ok: true;
	meta: {
		userId: string;
		pagesRequested: number;
		pagesFetched: number;
		postCount: number;
		truncated: boolean;
		nextToken: string | null;
		paginationTokenUsed: string | null;
		cached: boolean;
	};
	likedPosts: unknown[];
};

type ResearchAgentRpc = {
	startResearch(task: string): Promise<unknown>;
	getResearchStatus(instanceId: string): Promise<unknown>;
};

const app = new Hono<{ Bindings: Env }>();

app.notFound(() => json({ error: 'Not Found' }, 404));

app.onError((error) => {
	const message = error instanceof Error ? error.message : 'Unknown error';
	return json({ error: 'internal_error', detail: message }, 500);
});

app.use('/agents/*', async (c, next) => {
	const agentResponse = await routeAgentRequest(c.req.raw, c.env);
	if (agentResponse) {
		return agentResponse;
	}
	await next();
});

app.all('*', async (c) => {
	const request = c.req.raw;
	const env = c.env;
	const url = new URL(request.url);

	// HTTP API for starting research tasks
	if (request.method === 'POST' && url.pathname === '/research') {
		const { task, agentId } = (await request.json()) as {
			task?: string;
			agentId?: string;
		};

		if (!task || typeof task !== 'string') {
			return json({ error: 'task required' }, 400);
		}

		// Get agent instance by name (creates if it doesn't exist)
		const agent = (await getAgentByName(env.ResearchAgent as any, agentId ?? 'default')) as unknown as ResearchAgentRpc;
		const result = await agent.startResearch(task);
		return Response.json(result);
	}

	// Check workflow status
	if (url.pathname === '/status') {
		const instanceId = url.searchParams.get('instanceId');
		const agentId = url.searchParams.get('agentId') ?? 'default';

		if (!instanceId) {
			return Response.json({ error: 'instanceId required' }, { status: 400 });
		}

		const agent = (await getAgentByName(env.ResearchAgent as any, agentId)) as unknown as ResearchAgentRpc;
		const status = await agent.getResearchStatus(instanceId);
		return Response.json(status);
	}

	if (request.method === 'GET' && url.pathname === '/auth/x/login') {
		return startXOAuth(request, env);
	}

	if (request.method === 'GET' && url.pathname === '/auth/x/callback') {
		return handleXOAuthCallback(request, env);
	}

	if (request.method === 'GET' && url.pathname === '/x/liked-posts') {
		return handleLikedPosts(request, env);
	}

	if (request.method === 'GET' && url.pathname === '/x/liked-posts/websites') {
		return handleLikedPostsWebsites(request, env);
	}

	if (request.method === 'GET' && url.pathname === '/') {
		return new Response('Hello World!');
	}

	return json({ error: 'Not Found' }, 404);
});

export default app satisfies ExportedHandler<Env>;

async function startXOAuth(request: Request, env: Env): Promise<Response> {
	const redirectUri = getRedirectUri(request, env);
	const oauth2 = new OAuth2(getOAuth2Config(request, env, redirectUri));
	const state = randomHex(16);
	const codeVerifier = generateCodeVerifier();
	const codeChallenge = await generateCodeChallenge(codeVerifier);

	await oauth2.setPkceParameters(codeVerifier, codeChallenge);
	const authorizationUrl = await oauth2.getAuthorizationUrl(state);

	return new Response(null, {
		status: 302,
		headers: {
			Location: authorizationUrl,
			'Set-Cookie': buildPkceCookie(
				{
					state,
					codeVerifier,
					redirectUri,
				},
				new URL(redirectUri).protocol === 'https:',
			),
		},
	});
}

async function handleXOAuthCallback(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const code = url.searchParams.get('code');
	const state = url.searchParams.get('state');
	const oauthError = url.searchParams.get('error');
	const oauthErrorDescription = url.searchParams.get('error_description');
	const pkceCookieValue = getCookieValue(request.headers.get('Cookie'), PKCE_COOKIE);

	if (oauthError) {
		return json(
			{
				error: 'x_oauth_error',
				detail: oauthError,
				error_description: oauthErrorDescription ?? undefined,
			},
			400,
		);
	}

	if (!code || !state || !pkceCookieValue) {
		return json({ error: 'missing_oauth_parameters' }, 400);
	}

	const pkcePayload = parsePkceCookie(pkceCookieValue);
	if (!pkcePayload || pkcePayload.state !== state) {
		return json({ error: 'invalid_oauth_state' }, 400);
	}

	const oauth2 = new OAuth2(getOAuth2Config(request, env, pkcePayload.redirectUri));
	try {
		await oauth2.setPkceParameters(pkcePayload.codeVerifier);
		const tokens = await oauth2.exchangeCode(code, pkcePayload.codeVerifier);
		const client = new Client({ accessToken: tokens.access_token });

		const me = await client.users.getMe();
		if (!me.data?.id) {
			return json({ error: 'user_lookup_failed', detail: me.errors ?? null }, 502);
		}
		await saveXTokens(env, tokens, me.data.id);

		return json(
			{
				ok: true,
				user: me.data,
				tokens: {
					access_token: tokens.access_token,
					refresh_token: tokens.refresh_token ?? null,
					hasRefreshToken: Boolean(tokens.refresh_token),
					scope: tokens.scope ?? null,
					expires_in: tokens.expires_in,
					token_type: tokens.token_type,
				},
				next: {
					reauthenticateRoute: '/auth/x/login',
					likedPostsRoute: '/x/liked-posts',
					authorizationHeader: 'Optional when KV token storage is configured: Bearer <access_token>',
				},
			},
			200,
			{
				'Set-Cookie': clearPkceCookie(new URL(pkcePayload.redirectUri).protocol === 'https:'),
			},
		);
	} catch (error) {
		if (isRateLimitError(error)) {
			return json(
				{
					error: 'x_rate_limited',
					detail: 'X API rate limit reached.',
					rateLimit: extractRateLimitInfo(error),
				},
				429,
				{
					'Set-Cookie': clearPkceCookie(new URL(pkcePayload.redirectUri).protocol === 'https:'),
				},
			);
		}

		const message = error instanceof Error ? error.message : 'Unknown OAuth callback error';
		return json({ error: 'x_oauth_callback_failed', detail: message }, 502, {
			'Set-Cookie': clearPkceCookie(new URL(pkcePayload.redirectUri).protocol === 'https:'),
		});
	}
}

async function handleLikedPosts(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const requestId = randomHex(8);
	const providedAccessToken = getBearerToken(request.headers.get('Authorization'));
	const storedTokens = providedAccessToken ? null : await getStoredXTokens(env);
	console.log({
		event: 'liked_posts.request_received',
		requestId,
		path: url.pathname,
		hasProvidedAccessToken: Boolean(providedAccessToken),
		hasStoredTokens: Boolean(storedTokens),
		hasUserIdQueryParam: Boolean(url.searchParams.get('user_id')),
		hasPaginationToken: Boolean(url.searchParams.get('pagination_token')),
		cacheBust: isTruthyQueryParam(url.searchParams.get('cache_bust')),
	});

	if (!providedAccessToken && !storedTokens) {
		return json(
			{
				error: 'missing_access_token',
				detail: 'Provide Authorization: Bearer <access_token> or authorize once at /auth/x/login to store tokens in KV.',
			},
			401,
		);
	}

	const accessToken =
		providedAccessToken ??
		(await getValidStoredAccessToken({
			request,
			env,
			storedTokens,
		}));
	if (!accessToken) {
		return json(
			{
				error: 'x_reauthorization_required',
				detail: 'Stored token is missing or expired and could not be refreshed. Reauthorize at /auth/x/login.',
			},
			401,
		);
	}

	const client = new Client({ accessToken });
	let xApiCalls = 0;
	const queryUserId = url.searchParams.get('user_id');
	const userId = queryUserId ?? storedTokens?.userId ?? DEFAULT_X_USER_ID;

	try {
		console.log({
			event: 'liked_posts.user_id_resolved',
			requestId,
			source: queryUserId ? 'query' : storedTokens?.userId ? 'kv' : 'default',
			userId,
		});
		const resolvedUserId = userId;

		const pagesRequested = getBoundedInt(url.searchParams.get('pages'), 1, 1, Number.MAX_SAFE_INTEGER);
		if (pagesRequested > 1) {
			return json(
				{
					error: 'invalid_pages_parameter',
					detail: `Only one liked-posts page can be fetched per request. Use pagination_token with separate requests at least ${X_LIKED_POSTS_RATE_LIMIT_WINDOW_MINUTES} minutes apart.`,
				},
				400,
			);
		}

		const maxResults = getBoundedInt(url.searchParams.get('max_results'), DEFAULT_LIKED_POSTS_PER_PAGE, 5, MAX_LIKED_POSTS_PER_PAGE);
		const paginationToken = url.searchParams.get('pagination_token') ?? undefined;
		const cacheBust = isTruthyQueryParam(url.searchParams.get('cache_bust'));
		const cacheKey = buildLikedPostsCacheKey({
			userId: resolvedUserId,
			maxResults,
			paginationToken,
		});
		if (!cacheBust) {
			console.log({
				event: 'liked_posts.cache_lookup',
				requestId,
				cacheKey,
			});
			const cachedLikedPosts = await getLikedPostsCache(env, cacheKey);
			if (cachedLikedPosts) {
				console.log({
					event: 'liked_posts.cache_hit',
					requestId,
					postCount: cachedLikedPosts.meta.postCount,
					nextToken: cachedLikedPosts.meta.nextToken,
				});
				return json(
					{
						...cachedLikedPosts,
						meta: {
							...cachedLikedPosts.meta,
							cached: true,
						},
					},
					200,
				);
			}
			console.log({
				event: 'liked_posts.cache_miss',
				requestId,
			});
		} else {
			console.log({
				event: 'liked_posts.cache_bypassed',
				requestId,
				cacheKey,
			});
		}

		console.log({
			event: 'liked_posts.x_get_liked_posts.start',
			requestId,
			xApiCalls,
			resolvedUserId,
			maxResults,
			hasPaginationToken: Boolean(paginationToken),
		});
		xApiCalls += 1;
		const likedPostsResponse = await client.users.getLikedPosts(resolvedUserId, {
			maxResults,
			paginationToken,
			tweetFields: ['lang', 'author_id', 'created_at', 'public_metrics', 'entities'],
			userFields: ['created_at'],
			mediaFields: ['media_key', 'type', 'url', 'variants', 'preview_image_url'],
		});
		const likedPosts = likedPostsResponse.data ?? [];
		console.log({
			event: 'liked_posts.x_get_liked_posts.end',
			requestId,
			xApiCalls,
			resultCount: likedPosts.length,
			nextToken: likedPostsResponse.meta?.nextToken ?? null,
		});
		const responseBody: LikedPostsResponseBody = {
			ok: true,
			meta: {
				userId: resolvedUserId,
				pagesRequested,
				pagesFetched: 1,
				postCount: likedPosts.length,
				truncated: Boolean(likedPostsResponse.meta?.nextToken),
				nextToken: likedPostsResponse.meta?.nextToken ?? null,
				paginationTokenUsed: paginationToken ?? null,
				cached: false,
			},
			likedPosts,
		};
		await saveLikedPostsCache(env, cacheKey, responseBody);
		console.log({
			event: 'liked_posts.cache_write',
			requestId,
			cacheKey,
			ttlSeconds: null,
		});

		return json(responseBody, 200);
	} catch (error) {
		if (isRateLimitError(error)) {
			const status = typeof (error as { status?: unknown }).status === 'number' ? (error as { status: number }).status : null;
			const message = error instanceof Error ? error.message : null;
			console.log({
				event: 'liked_posts.rate_limited',
				requestId,
				xApiCalls,
				status,
				message,
				rateLimit: extractRateLimitInfo(error),
			});
			return json(
				{
					error: 'x_rate_limited',
					detail: 'X API rate limit reached.',
					rateLimit: extractRateLimitInfo(error),
				},
				429,
			);
		}

		const message = error instanceof Error ? error.message : 'Unknown liked posts error';
		console.log({
			event: 'liked_posts.failed',
			requestId,
			xApiCalls,
			error: message,
		});
		return json({ error: 'x_liked_posts_failed', detail: message }, 502);
	}
}

async function handleLikedPostsWebsites(request: Request, env: Env): Promise<Response> {
	const likedPostsResponse = await handleLikedPosts(request, env);
	if (!likedPostsResponse.ok) {
		return likedPostsResponse;
	}

	let payload: LikedPostsResponseBody;
	try {
		payload = (await likedPostsResponse.clone().json()) as LikedPostsResponseBody;
	} catch {
		return json({ error: 'invalid_liked_posts_payload' }, 502);
	}

	const likedPostsWithWebsites = payload.likedPosts.map((post) => {
		const safePost = typeof post === 'object' && post !== null ? (post as Record<string, unknown>) : { raw: post };
		return {
			...safePost,
			websiteUrls: extractWebsiteUrlsFromPost(post),
		};
	});

	return json(
		{
			...payload,
			likedPosts: likedPostsWithWebsites,
		},
		200,
	);
}

function getOAuth2Config(request: Request, env: Env, redirectUri: string): OAuth2Config {
	const clientId = getOptionalEnv(env, 'X_API_CLIENT_ID') ?? getRequiredEnv(env, 'CLIENT_ID');
	const clientSecret = getOptionalEnv(env, 'X_API_CLIENT_SECRET') ?? getOptionalEnv(env, 'CLIENT_SECRET');
	const scope = getScopes(env);

	const config: OAuth2Config = {
		clientId,
		redirectUri,
		scope,
	};

	if (clientSecret) {
		config.clientSecret = clientSecret;
	}

	return config;
}

async function getValidStoredAccessToken({
	request,
	env,
	storedTokens,
}: {
	request: Request;
	env: Env;
	storedTokens: StoredXTokens | null;
}): Promise<string | null> {
	if (!storedTokens) {
		return null;
	}

	const hasUsableAccessToken =
		storedTokens.accessToken.length > 0 &&
		(storedTokens.expiresAt === null || !isExpiringSoon(storedTokens.expiresAt, ACCESS_TOKEN_REFRESH_BUFFER_SECONDS));
	if (hasUsableAccessToken) {
		return storedTokens.accessToken;
	}

	if (!storedTokens.refreshToken) {
		return null;
	}

	const oauth2 = new OAuth2(getOAuth2Config(request, env, getRedirectUri(request, env)));
	const refreshed = await oauth2.refreshToken(storedTokens.refreshToken);
	await saveXTokens(env, refreshed);
	return refreshed.access_token;
}

async function getStoredXTokens(env: Env): Promise<StoredXTokens | null> {
	if (!('X_AUTH_KV' in env) || !env.X_AUTH_KV) {
		return null;
	}

	const raw = await env.X_AUTH_KV.get(X_TOKENS_KV_KEY, 'json');
	if (!raw || typeof raw !== 'object') {
		return null;
	}

	const parsed = raw as Partial<StoredXTokens>;
	if (typeof parsed.accessToken !== 'string' || typeof parsed.tokenType !== 'string' || typeof parsed.updatedAt !== 'number') {
		return null;
	}

	const expiresAt = typeof parsed.expiresAt === 'number' ? parsed.expiresAt : null;
	const refreshToken = typeof parsed.refreshToken === 'string' ? parsed.refreshToken : null;
	const scope = typeof parsed.scope === 'string' ? parsed.scope : null;
	const userId = typeof parsed.userId === 'string' ? parsed.userId : null;

	return {
		accessToken: parsed.accessToken,
		refreshToken,
		tokenType: parsed.tokenType,
		scope,
		expiresAt,
		userId,
		updatedAt: parsed.updatedAt,
	};
}

async function saveXTokens(
	env: Env,
	tokens: {
		access_token: string;
		refresh_token?: string;
		token_type: string;
		scope?: string;
		expires_in?: number;
	},
	userId?: string | null,
): Promise<void> {
	if (!('X_AUTH_KV' in env) || !env.X_AUTH_KV) {
		return;
	}

	const previous = await getStoredXTokens(env);
	const stored: StoredXTokens = {
		accessToken: tokens.access_token,
		refreshToken: tokens.refresh_token ?? previous?.refreshToken ?? null,
		tokenType: tokens.token_type,
		scope: tokens.scope ?? null,
		expiresAt: typeof tokens.expires_in === 'number' ? Date.now() + tokens.expires_in * 1000 : null,
		userId: userId ?? previous?.userId ?? null,
		updatedAt: Date.now(),
	};

	await env.X_AUTH_KV.put(X_TOKENS_KV_KEY, JSON.stringify(stored));
}

async function getLikedPostsCache(env: Env, key: string): Promise<LikedPostsResponseBody | null> {
	if (!('X_AUTH_KV' in env) || !env.X_AUTH_KV) {
		return null;
	}

	const cached = await env.X_AUTH_KV.get<LikedPostsResponseBody>(key, 'json');
	if (!cached || typeof cached !== 'object') {
		return null;
	}

	if (
		typeof cached.meta?.userId !== 'string' ||
		typeof cached.meta?.pagesRequested !== 'number' ||
		typeof cached.meta?.pagesFetched !== 'number' ||
		typeof cached.meta?.postCount !== 'number' ||
		typeof cached.meta?.truncated !== 'boolean'
	) {
		return null;
	}

	if (!Array.isArray(cached.likedPosts)) {
		return null;
	}

	return cached;
}

async function saveLikedPostsCache(env: Env, key: string, responseBody: LikedPostsResponseBody): Promise<void> {
	if (!('X_AUTH_KV' in env) || !env.X_AUTH_KV) {
		return;
	}

	await env.X_AUTH_KV.put(key, JSON.stringify(responseBody));
}

function buildLikedPostsCacheKey({
	userId,
	maxResults,
	paginationToken,
}: {
	userId: string;
	maxResults: number;
	paginationToken?: string;
}): string {
	const tokenPart = paginationToken ? encodeURIComponent(paginationToken) : 'none';
	return `${X_LIKED_POSTS_CACHE_KEY_PREFIX}:${userId}:${maxResults}:${tokenPart}`;
}

function extractWebsiteUrlsFromPost(post: unknown): string[] {
	if (typeof post !== 'object' || post === null) {
		return [];
	}

	const entities = (post as { entities?: unknown }).entities;
	if (typeof entities !== 'object' || entities === null) {
		return [];
	}

	const rawUrls = (entities as { urls?: unknown }).urls;
	if (!Array.isArray(rawUrls)) {
		return [];
	}

	const urls = rawUrls
		.map((item) => {
			if (typeof item !== 'object' || item === null) {
				return null;
			}
			const entity = item as {
				unwoundUrl?: unknown;
				expandedUrl?: unknown;
				url?: unknown;
				mediaKey?: unknown;
			};

			const candidate =
				typeof entity.unwoundUrl === 'string'
					? entity.unwoundUrl
					: typeof entity.expandedUrl === 'string'
						? entity.expandedUrl
						: typeof entity.url === 'string'
							? entity.url
							: null;
			if (!candidate || !isWebsiteUrl(candidate, entity)) {
				return null;
			}
			return candidate;
		})
		.filter((url): url is string => Boolean(url));

	return Array.from(new Set(urls));
}

function isWebsiteUrl(url: string, entity?: { mediaKey?: unknown }): boolean {
	if (entity && typeof entity.mediaKey === 'string' && entity.mediaKey.length > 0) {
		return false;
	}

	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}

	if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
		return false;
	}

	const host = parsed.hostname.toLowerCase();
	if (host === 'pic.x.com' || host === 'pbs.twimg.com' || host === 'video.twimg.com') {
		return false;
	}

	const path = parsed.pathname.toLowerCase();
	const isXDomain = host === 'x.com' || host.endsWith('.x.com') || host === 'twitter.com' || host.endsWith('.twitter.com');
	if (isXDomain && (path.includes('/photo/') || path.includes('/video/'))) {
		return false;
	}

	if (/\.(jpg|jpeg|png|gif|webp|svg|avif|bmp|ico|mp4|mov|webm|m4v|avi)$/i.test(path)) {
		return false;
	}

	return true;
}

function getRedirectUri(request: Request, env: Env): string {
	const configured = getOptionalEnv(env, 'X_OAUTH_REDIRECT_URI');
	if (configured) {
		return configured;
	}

	return `${new URL(request.url).origin}/auth/x/callback`;
}

function getScopes(env: Env): string[] {
	const configured = getOptionalEnv(env, 'X_OAUTH_SCOPES');
	if (!configured) {
		return DEFAULT_SCOPES;
	}

	const scopes = configured
		.split(/\s+/)
		.map((scope) => scope.trim())
		.filter(Boolean);
	return scopes.length > 0 ? scopes : DEFAULT_SCOPES;
}

function getRequiredEnv(env: Env, key: string): string {
	const value = getOptionalEnv(env, key);
	if (!value) {
		throw new Error(`Missing required environment variable: ${key}`);
	}
	return value;
}

function getBoundedInt(value: string | null, defaultValue: number, minValue: number, maxValue: number): number {
	if (!value) {
		return defaultValue;
	}

	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) {
		return defaultValue;
	}

	return Math.max(minValue, Math.min(maxValue, parsed));
}

function isTruthyQueryParam(value: string | null): boolean {
	if (!value) {
		return false;
	}

	const normalized = value.trim().toLowerCase();
	return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function isExpiringSoon(expiresAtEpochMs: number, bufferSeconds: number): boolean {
	const threshold = Date.now() + bufferSeconds * 1000;
	return expiresAtEpochMs <= threshold;
}

function isRateLimitError(error: unknown): error is { status?: number; message?: string; headers?: Headers } {
	if (!(error instanceof Error)) {
		return false;
	}

	const withStatus = error as Error & { status?: number };
	return withStatus.status === 429 || error.message.toLowerCase().includes('rate limit');
}

function extractRateLimitInfo(error: { headers?: Headers }): {
	retryAfterSeconds: string | null;
	limit: string | null;
	remaining: string | null;
	resetEpochSeconds: string | null;
} {
	const headers = error.headers;
	return {
		retryAfterSeconds: headers?.get('retry-after') ?? null,
		limit: headers?.get('x-rate-limit-limit') ?? null,
		remaining: headers?.get('x-rate-limit-remaining') ?? null,
		resetEpochSeconds: headers?.get('x-rate-limit-reset') ?? null,
	};
}

function getOptionalEnv(env: Env, key: string): string | undefined {
	const value = (env as unknown as EnvMap)[key];
	if (typeof value !== 'string') {
		return undefined;
	}
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

function getBearerToken(authorization: string | null): string | null {
	if (!authorization) {
		return null;
	}
	const [scheme, token] = authorization.split(/\s+/, 2);
	if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
		return null;
	}
	return token.trim() || null;
}

function randomHex(byteLength: number): string {
	const bytes = new Uint8Array(byteLength);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function buildPkceCookie(payload: { state: string; codeVerifier: string; redirectUri: string }, secure: boolean): string {
	const encoded = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
	const secureFlag = secure ? '; Secure' : '';
	return `${PKCE_COOKIE}=${encoded}; Max-Age=${PKCE_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;
}

function clearPkceCookie(secure: boolean): string {
	const secureFlag = secure ? '; Secure' : '';
	return `${PKCE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;
}

function parsePkceCookie(value: string): { state: string; codeVerifier: string; redirectUri: string } | null {
	try {
		const decoded = decodeBase64Url(value);
		const parsed = JSON.parse(decoded) as {
			state?: string;
			codeVerifier?: string;
			redirectUri?: string;
		};

		if (!parsed.state || !parsed.codeVerifier || !parsed.redirectUri) {
			return null;
		}

		return {
			state: parsed.state,
			codeVerifier: parsed.codeVerifier,
			redirectUri: parsed.redirectUri,
		};
	} catch {
		return null;
	}
}

function getCookieValue(cookieHeader: string | null, key: string): string | null {
	if (!cookieHeader) {
		return null;
	}

	for (const part of cookieHeader.split(';')) {
		const [name, ...rest] = part.trim().split('=');
		if (name === key) {
			return rest.join('=') || null;
		}
	}

	return null;
}

function encodeBase64Url(input: Uint8Array): string {
	let binary = '';
	for (const byte of input) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(input: string): string {
	const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
	const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
	return atob(padded);
}

function json(body: unknown, status: number, headers?: HeadersInit): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			...headers,
		},
	});
}

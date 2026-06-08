const AUTH_CODE_TTL_SECONDS = 300
const ID_TOKEN_TTL_SECONDS = 3600

const GIVEN_NAME_POOL = [
  'Aiden',
  'Alice',
  'Amelia',
  'Aria',
  'Avery',
  'Bella',
  'Blake',
  'Caleb',
  'Chloe',
  'Daniel',
  'Dylan',
  'Emma',
  'Ethan',
  'Felix',
  'Grace',
  'Harper',
  'Henry',
  'Iris',
  'Jack',
  'Jasper',
  'Leo',
  'Liam',
  'Lily',
  'Logan',
  'Lucas',
  'Mason',
  'Mia',
  'Noah',
  'Nora',
  'Olivia',
  'Owen',
  'Ruby',
  'Ryan',
  'Sofia',
  'Theo',
  'Violet',
  'William',
  'Zoe'
] as const

const FAMILY_NAME_POOL = [
  'Anderson',
  'Bennett',
  'Brooks',
  'Carter',
  'Chen',
  'Clark',
  'Cooper',
  'Davis',
  'Evans',
  'Foster',
  'Garcia',
  'Green',
  'Hall',
  'Harris',
  'Hill',
  'Hughes',
  'Johnson',
  'King',
  'Lee',
  'Lewis',
  'Martin',
  'Miller',
  'Mitchell',
  'Morgan',
  'Nelson',
  'Parker',
  'Reed',
  'Rivera',
  'Roberts',
  'Scott',
  'Smith',
  'Taylor',
  'Thomas',
  'Turner',
  'Walker',
  'Wang',
  'White',
  'Young'
] as const

type Env = {
  ASSETS: Fetcher
  AUTH_CODES: DurableObjectNamespace
  ISSUER?: string
  OIDC_CLIENT_ID?: string
  OIDC_CLIENT_SECRET?: string
  OIDC_REDIRECT_URI?: string
  OIDC_PRIVATE_JWK?: string
}

type User = {
  sub: string
  email: string
  given_name: string
  family_name: string
}

type AuthCode = {
  user: User
  client_id: string
  nonce: string
  auth_time: number
  expires_at: number
}

type LoginRequest = {
  email?: string
  password?: string
  client_id?: string
  nonce?: string
}

type PrivateJwk = JsonWebKey & {
  kty: 'RSA'
  n: string
  e: string
}

type ClientCredentials = {
  clientId: string
  clientSecret: string
}

function getConfig(request: Request, env: Env) {
  const origin = new URL(request.url).origin

  return {
    issuer: trimTrailingSlash(env.ISSUER || origin),
    clientId: env.OIDC_CLIENT_ID || 'openai-workspace',
    clientSecret: env.OIDC_CLIENT_SECRET || '',
    allowedRedirectUri: env.OIDC_REDIRECT_URI || ''
  }
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'GET' && url.pathname === '/') {
      return Response.redirect(`${url.origin}/ui/`, 302)
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return handleDiscovery(request, env)
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/jwks.json') {
      return handleJwks(env)
    }

    if (request.method === 'GET' && url.pathname === '/authorize') {
      return handleAuthorize(request, env)
    }

    if (request.method === 'POST' && url.pathname === '/token') {
      return handleToken(request, env)
    }

    if (request.method === 'POST' && url.pathname === '/api/login') {
      return handleLogin(request, env)
    }

    if (request.method === 'GET' && (url.pathname === '/ui' || url.pathname === '/ui/' || url.pathname === '/ui/login')) {
      return serveUiIndex(request, env)
    }

    return env.ASSETS.fetch(request)
  }
} satisfies ExportedHandler<Env>

async function handleDiscovery(request: Request, env: Env): Promise<Response> {
  const config = getConfig(request, env)

  return jsonResponse({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    scopes_supported: ['openid', 'email', 'profile'],
    claims_supported: [
      'iss',
      'aud',
      'sub',
      'email',
      'email_verified',
      'given_name',
      'family_name',
      'exp',
      'iat',
      'auth_time',
      'nonce'
    ]
  })
}

async function handleJwks(env: Env): Promise<Response> {
  const privateJwk = parsePrivateJwk(env)
  if (privateJwk instanceof Response) {
    return privateJwk
  }

  const kid = await makeKeyId(privateJwk)

  // JWKS 只暴露 RSA 公钥参数 n/e，不暴露 d/p/q 等私钥字段。
  // OpenAI 会通过 kid 找到这把公钥，并用它验证 /token 返回的 ID Token 签名。
  return jsonResponse({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        kid,
        alg: 'RS256',
        n: privateJwk.n,
        e: privateJwk.e
      }
    ]
  })
}

function handleAuthorize(request: Request, env: Env): Response {
  const url = new URL(request.url)
  const config = getConfig(request, env)
  const clientId = url.searchParams.get('client_id') || ''
  const redirectUri = url.searchParams.get('redirect_uri') || ''
  const responseType = url.searchParams.get('response_type') || ''
  const state = url.searchParams.get('state') || ''
  const nonce = url.searchParams.get('nonce') || ''

  if (responseType !== 'code') {
    return errorResponse(400, 'unsupported_response_type', '只支持 authorization code flow')
  }
  if (clientId !== config.clientId) {
    return errorResponse(400, 'invalid_client', 'client_id 不匹配')
  }
  if (!redirectUri) {
    return errorResponse(400, 'invalid_request', 'redirect_uri 不能为空')
  }
  if (config.allowedRedirectUri && redirectUri !== config.allowedRedirectUri) {
    return errorResponse(400, 'invalid_request', 'redirect_uri 不在允许列表中')
  }

  const loginUrl = new URL('/ui/', url.origin)
  loginUrl.searchParams.set('client_id', clientId)
  loginUrl.searchParams.set('redirect_uri', redirectUri)
  loginUrl.searchParams.set('state', state)
  if (nonce) {
    loginUrl.searchParams.set('nonce', nonce)
  }

  return Response.redirect(loginUrl.toString(), 302)
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const config = getConfig(request, env)
  let body: LoginRequest

  try {
    body = await request.json<LoginRequest>()
  } catch {
    return errorResponse(400, 'invalid_request', '请求体必须是 JSON，且包含 email/password')
  }

  if (body.client_id && body.client_id !== config.clientId) {
    return errorResponse(400, 'invalid_client', 'client_id 不匹配')
  }

  const user = validateUser(body.email || '', body.password || '')
  if (!user) {
    return errorResponse(401, 'invalid_credentials', '邮箱或密码错误')
  }

  const authCodes = getAuthCodeStore(env)
  const response = await authCodes.fetch('https://auth-codes/create', {
    method: 'POST',
    body: JSON.stringify({
      user,
      client_id: body.client_id || config.clientId,
      nonce: body.nonce || ''
    })
  })

  return response
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  const config = getConfig(request, env)
  if (!config.clientSecret) {
    return errorResponse(500, 'server_error', 'OIDC_CLIENT_SECRET 未配置')
  }
  const privateJwk = parsePrivateJwk(env)
  if (privateJwk instanceof Response) {
    return privateJwk
  }

  const form = await request.formData()
  const grantType = getFormValue(form, 'grant_type')
  if (grantType !== 'authorization_code') {
    return errorResponse(400, 'unsupported_grant_type', '只支持 authorization_code')
  }

  const credentials = readClientCredentials(request, form)
  if (credentials.clientId !== config.clientId || credentials.clientSecret !== config.clientSecret) {
    return errorResponse(401, 'invalid_client', 'client_id 或 client_secret 不正确', {
      'WWW-Authenticate': 'Basic realm="omni-sso"'
    })
  }

  const code = getFormValue(form, 'code')
  if (!code) {
    return errorResponse(400, 'invalid_request', 'code 不能为空')
  }

  const authCodes = getAuthCodeStore(env)
  const consumeResponse = await authCodes.fetch('https://auth-codes/consume', {
    method: 'POST',
    body: JSON.stringify({ code })
  })

  if (!consumeResponse.ok) {
    return errorResponse(400, 'invalid_grant', 'code 无效或已过期')
  }

  const authCode = await consumeResponse.json<AuthCode>()
  if (authCode.client_id && authCode.client_id !== credentials.clientId) {
    return errorResponse(400, 'invalid_grant', 'code 与 client_id 不匹配')
  }

  const idToken = await signIdToken(config.issuer, credentials.clientId, authCode, privateJwk)

  return jsonResponse({
    access_token: idToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: ID_TOKEN_TTL_SECONDS,
    scope: 'openid email profile'
  })
}

function validateUser(rawEmail: string, password: string): User | null {
  const email = rawEmail.trim().toLowerCase()
  const at = email.indexOf('@')
  if (at <= 0 || at === email.length - 1) {
    return null
  }

  const prefix = email.slice(0, at)
  if (!timingSafeEqual(prefix, password)) {
    return null
  }

  return {
    sub: email,
    email,
    ...randomNameClaims()
  }
}

function randomNameClaims(): Pick<User, 'given_name' | 'family_name'> {
  return {
    given_name: randomChoice(GIVEN_NAME_POOL),
    family_name: randomChoice(FAMILY_NAME_POOL)
  }
}

function randomChoice<T>(items: readonly T[]): T {
  const bytes = new Uint32Array(1)
  crypto.getRandomValues(bytes)

  return items[bytes[0] % items.length]
}

async function signIdToken(issuer: string, clientId: string, authCode: AuthCode, privateJwk: PrivateJwk): Promise<string> {
  const kid = await makeKeyId(privateJwk)
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  )

  const now = Math.floor(Date.now() / 1000)

  // ID Token 是 OpenID Connect 登录成功后的核心凭证。
  // 这里用 Cloudflare secret 中的 RSA 私钥执行 RS256 签名；
  // OpenAI 会拉取 JWKS 公钥并校验签名、issuer、audience 和过期时间。
  const payload: Record<string, string | number | boolean> = {
    iss: issuer,
    aud: clientId,
    sub: authCode.user.sub,
    email: authCode.user.email,
    email_verified: true,
    given_name: authCode.user.given_name,
    family_name: authCode.user.family_name,
    iat: now,
    auth_time: authCode.auth_time,
    exp: now + ID_TOKEN_TTL_SECONDS
  }
  if (authCode.nonce) {
    payload.nonce = authCode.nonce
  }

  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid
  }

  const unsignedToken = `${base64UrlJson(header)}.${base64UrlJson(payload)}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsignedToken)
  )

  return `${unsignedToken}.${base64UrlBytes(new Uint8Array(signature))}`
}

function parsePrivateJwk(env: Env): PrivateJwk | Response {
  if (!env.OIDC_PRIVATE_JWK) {
    return errorResponse(500, 'server_error', 'OIDC_PRIVATE_JWK 未配置')
  }

  try {
    const jwk = JSON.parse(env.OIDC_PRIVATE_JWK) as PrivateJwk
    if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.d) {
      return errorResponse(500, 'server_error', 'OIDC_PRIVATE_JWK 必须是 RSA 私钥 JWK')
    }
    return jwk
  } catch {
    return errorResponse(500, 'server_error', 'OIDC_PRIVATE_JWK 不是合法 JSON')
  }
}

async function makeKeyId(jwk: PrivateJwk): Promise<string> {
  const thumbprintInput = JSON.stringify({
    e: jwk.e,
    kty: jwk.kty,
    n: jwk.n
  })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput))

  return base64UrlBytes(new Uint8Array(digest)).slice(0, 16)
}

function readClientCredentials(request: Request, form: FormData): ClientCredentials {
  const formClientId = getFormValue(form, 'client_id')
  const formClientSecret = getFormValue(form, 'client_secret')
  if (formClientId || formClientSecret) {
    return {
      clientId: formClientId,
      clientSecret: formClientSecret
    }
  }

  const authorization = request.headers.get('Authorization') || ''
  if (!authorization.startsWith('Basic ')) {
    return {
      clientId: '',
      clientSecret: ''
    }
  }

  try {
    const decoded = atob(authorization.slice('Basic '.length))
    const colon = decoded.indexOf(':')
    if (colon < 0) {
      return {
        clientId: '',
        clientSecret: ''
      }
    }

    return {
      clientId: decoded.slice(0, colon),
      clientSecret: decoded.slice(colon + 1)
    }
  } catch {
    return {
      clientId: '',
      clientSecret: ''
    }
  }
}

function getFormValue(form: FormData, name: string): string {
  const value = form.get(name)
  return typeof value === 'string' ? value : ''
}

function getAuthCodeStore(env: Env): DurableObjectStub {
  const id = env.AUTH_CODES.idFromName('global-auth-code-store')
  return env.AUTH_CODES.get(id)
}

async function serveUiIndex(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  if (url.pathname === '/ui') {
    return Response.redirect(`${url.origin}/ui/${url.search}`, 302)
  }

  const indexUrl = new URL('/ui/index.html', url.origin)
  return env.ASSETS.fetch(
    new Request(indexUrl.toString(), {
      method: 'GET',
      headers: request.headers
    })
  )
}

function jsonResponse(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'application/json; charset=utf-8')

  return new Response(JSON.stringify(data), {
    ...init,
    headers
  })
}

function errorResponse(status: number, error: string, description: string, headers?: HeadersInit): Response {
  return jsonResponse(
    {
      error,
      error_description: description
    },
    {
      status,
      headers
    }
  )
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '')
}

function base64UrlJson(value: unknown): string {
  return base64UrlBytes(new TextEncoder().encode(JSON.stringify(value)))
}

function base64UrlBytes(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a)
  const bBytes = new TextEncoder().encode(b)
  const max = Math.max(aBytes.length, bBytes.length)
  let diff = aBytes.length ^ bBytes.length

  for (let index = 0; index < max; index += 1) {
    diff |= (aBytes[index] || 0) ^ (bBytes[index] || 0)
  }

  return diff === 0
}

export class AuthCodeStore {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'POST' && url.pathname === '/create') {
      return this.createCode(request)
    }

    if (request.method === 'POST' && url.pathname === '/consume') {
      return this.consumeCode(request)
    }

    return errorResponse(404, 'not_found', '授权码存储接口不存在')
  }

  private async createCode(request: Request): Promise<Response> {
    const body = await request.json<{
      user: User
      client_id: string
      nonce: string
    }>()

    const code = randomToken(32)
    const now = Math.floor(Date.now() / 1000)
    const authCode: AuthCode = {
      user: body.user,
      client_id: body.client_id,
      nonce: body.nonce,
      auth_time: now,
      expires_at: now + AUTH_CODE_TTL_SECONDS
    }

    // Durable Object 提供强一致存储，避免 /api/login 写入 code 后，
    // /token 在另一个边缘节点立即读取时出现普通内存或 eventually-consistent KV 的问题。
    await this.cleanupExpiredCodes(now)
    await this.state.storage.put(`code:${code}`, authCode)

    return jsonResponse({
      code,
      expires_in: AUTH_CODE_TTL_SECONDS
    })
  }

  private async consumeCode(request: Request): Promise<Response> {
    const body = await request.json<{
      code?: string
    }>()

    if (!body.code) {
      return errorResponse(400, 'invalid_request', 'code 不能为空')
    }

    const key = `code:${body.code}`
    const authCode = await this.state.storage.get<AuthCode>(key)
    if (!authCode) {
      return errorResponse(404, 'invalid_grant', 'code 无效')
    }

    await this.state.storage.delete(key)

    if (Math.floor(Date.now() / 1000) > authCode.expires_at) {
      return errorResponse(410, 'invalid_grant', 'code 已过期')
    }

    return jsonResponse(authCode)
  }

  private async cleanupExpiredCodes(now: number): Promise<void> {
    const codes = await this.state.storage.list<AuthCode>({
      prefix: 'code:'
    })

    const deleteKeys: string[] = []
    for (const [key, authCode] of codes) {
      if (now > authCode.expires_at) {
        deleteKeys.push(key)
      }
    }

    if (deleteKeys.length > 0) {
      await this.state.storage.delete(deleteKeys)
    }
  }
}

function randomToken(byteLength: number): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)

  return base64UrlBytes(bytes)
}

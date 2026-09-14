const REDIRECT_URI =
  "https://smart-edge-engine.khayumbikevin87.workers.dev/auth/callback";

const DERIV_AUTH_URL = "https://auth.deriv.com/oauth2/auth";
const DERIV_TOKEN_URL = "https://auth.deriv.com/oauth2/token";

const ACCESS_COOKIE = "sse_access_token";
const STATE_COOKIE = "sse_oauth_state";
const VERIFIER_COOKIE = "sse_pkce_verifier";

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function createPkce() {
  const verifier = base64Url(randomBytes(64));

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );

  const challenge = base64Url(new Uint8Array(hash));

  return { verifier, challenge };
}

function cookie(name, value, maxAge) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ].join("; ");
}

function deleteCookie(name) {
  return [
    `${name}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();

    if (key === name) {
      return decodeURIComponent(
        part.slice(index + 1)
      );
    }
  }

  return null;
}

function html(title, message) {
  return new Response(
    `<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
body{
  margin:0;
  padding:30px;
  background:#07101f;
  color:white;
  font-family:Arial,sans-serif;
  text-align:center;
}
.box{
  max-width:500px;
  margin:60px auto;
  background:#111c2f;
  padding:25px;
  border-radius:15px;
}
h1{font-size:24px}
p{color:#cbd5e1;line-height:1.6}
button{
  border:0;
  border-radius:9px;
  padding:13px 20px;
  background:#2563eb;
  color:white;
  font-weight:bold;
  font-size:16px;
}
</style>
</head>
<body>
<div class="box">
<h1>${title}</h1>
<p>${message}</p>
<button onclick="location.href='/'">
Return to Smart Edge Engine
</button>
</div>
</body>
</html>`,
    {
      headers: {
        "Content-Type": "text/html; charset=UTF-8"
      }
    }
  );
}

async function handleLogin(env) {
  if (!env.DERIV_CLIENT_ID) {
    return html(
      "Configuration Required",
      "DERIV_CLIENT_ID has not been configured in Cloudflare."
    );
  }

  const { verifier, challenge } = await createPkce();

  const state = base64Url(randomBytes(32));

  const authUrl = new URL(DERIV_AUTH_URL);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set(
    "client_id",
    env.DERIV_CLIENT_ID
  );
  authUrl.searchParams.set(
    "redirect_uri",
    REDIRECT_URI
  );
  authUrl.searchParams.set("scope", "trade");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set(
    "code_challenge",
    challenge
  );
  authUrl.searchParams.set(
    "code_challenge_method",
    "S256"
  );

  const headers = new Headers();

  headers.set(
    "Location",
    authUrl.toString()
  );

  headers.append(
    "Set-Cookie",
    cookie(STATE_COOKIE, state, 600)
  );

  headers.append(
    "Set-Cookie",
    cookie(VERIFIER_COOKIE, verifier, 600)
  );

  return new Response(null, {
    status: 302,
    headers
  });
}

async function handleCallback(request, env) {
  const url = new URL(request.url);

  const error = url.searchParams.get("error");

  if (error) {
    return html(
      "Deriv Login Cancelled",
      error
    );
  }

  const code = url.searchParams.get("code");
  const returnedState =
    url.searchParams.get("state");

  const savedState =
    getCookie(request, STATE_COOKIE);

  const verifier =
    getCookie(request, VERIFIER_COOKIE);

  if (!code) {
    return html(
      "Login Error",
      "Deriv did not return an authorization code."
    );
  }

  if (
    !returnedState ||
    !savedState ||
    returnedState !== savedState
  ) {
    return html(
      "Security Error",
      "OAuth state verification failed. Please start again."
    );
  }

  if (!verifier) {
    return html(
      "Security Error",
      "PKCE verification value is missing. Please start again."
    );
  }

  const body = new URLSearchParams();

  body.set(
    "grant_type",
    "authorization_code"
  );

  body.set(
    "client_id",
    env.DERIV_CLIENT_ID
  );

  body.set("code", code);

  body.set(
    "code_verifier",
    verifier
  );

  body.set(
    "redirect_uri",
    REDIRECT_URI
  );

  const tokenResponse = await fetch(
    DERIV_TOKEN_URL,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const tokenData =
    await tokenResponse.json();

  if (
    !tokenResponse.ok ||
    !tokenData.access_token
  ) {
    console.error(
      "Deriv OAuth token exchange failed"
    );

    return html(
      "Connection Failed",
      "Deriv did not issue an access token. Check the App ID and redirect URI."
    );
  }

  const expiresIn =
    Number(tokenData.expires_in || 3600);

  const headers = new Headers();

  headers.set(
    "Location",
    "/?deriv=connected"
  );

  headers.append(
    "Set-Cookie",
    cookie(
      ACCESS_COOKIE,
      tokenData.access_token,
      expiresIn
    )
  );

  headers.append(
    "Set-Cookie",
    deleteCookie(STATE_COOKIE)
  );

  headers.append(

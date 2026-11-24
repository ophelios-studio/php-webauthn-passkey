function b64urlToBuffer(b64url) {
    const pad = (str) => str + "=".repeat((4 - (str.length % 4)) % 4);
    const b64 = pad(String(b64url).replace(/-/g, "+").replace(/_/g, "/"));
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
}

function bufferToB64url(buf) {
    const bin = String.fromCharCode.apply(null, new Uint8Array(buf));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function encodePrfResultsFromCredential(cred) {
    try {
        if (!cred || typeof cred.getClientExtensionResults !== 'function') return null;
        const ext = cred.getClientExtensionResults();
        const prf = ext && ext.prf && ext.prf.results
            ? ext.prf.results
            : (ext && ext.prfResults && ext.prfResults.results ? ext.prfResults.results : null);
        if (!prf) return null;
        const out = {};
        if (prf.first) out.first = bufferToB64url(prf.first);
        if (prf.second) out.second = bufferToB64url(prf.second);
        return out;
    } catch (_) {
        return null;
    }
}

function credToJSON(c) {
    return {
        id: c.id,
        type: c.type,
        rawId: bufferToB64url(c.rawId),
        response: {
            // For registration (attestation)
            clientDataJSON: bufferToB64url(c.response.clientDataJSON),
            attestationObject: c.response.attestationObject ? bufferToB64url(c.response.attestationObject) : undefined,
            transports: typeof c.response.getTransports === 'function' ? c.response.getTransports() : undefined,
            // For login (assertion) - these will be undefined during create()
            authenticatorData: c.response.authenticatorData ? bufferToB64url(c.response.authenticatorData) : undefined,
            signature: c.response.signature ? bufferToB64url(c.response.signature) : undefined,
            userHandle: c.response.userHandle ? bufferToB64url(c.response.userHandle) : undefined,
        },
        clientExtensionResults: extensionResultsForServer(c),
    };
}

/**
 * The client extension results the server may see: every one but the PRF output, which stays in the
 * browser under both the standard key (prf) and the one earlier versions posted (prfResults).
 */
function extensionResultsForServer(c) {
    const ext = typeof c.getClientExtensionResults === 'function' ? c.getClientExtensionResults() : null;
    const out = {};
    if (ext && typeof ext === 'object') {
        for (const key of Object.keys(ext)) {
            if (key !== 'prf' && key !== 'prfResults') out[key] = ext[key];
        }
    }
    return out;
}

/**
 * The result of a verified ceremony: the server's verification JSON, plus the PRF output (base64url)
 * when the caller asked for it and the authenticator returned it. It never leaves the browser.
 */
function verifiedResult(serverJson, cred, prfEnabled) {
    const result = { ...serverJson, ok: true };
    delete result.prf;
    const prf = prfEnabled ? encodePrfResultsFromCredential(cred) : null;
    if (prf && prf.first) {
        result.prf = prf;
    }
    return result;
}

/**
 * Perform a passkey registration (WebAuthn create/attestation).
 * @param {Object} cfg
 * @param {string} [cfg.optionsUrl="/webauthn/register/options"] - Creation options endpoint.
 * @param {string} [cfg.verifyUrl="/webauthn/register/verify"] - Verification endpoint.
 * @param {{enabled: boolean}} [cfg.prf] - Request the PRF output; it is returned, never posted.
 * @returns {Promise<{ok: boolean, err?: string, prf?: {first: string, second?: string}}>} on success, the
 *          server's verification JSON with ok true, plus the PRF output in base64url when requested and returned.
 */
export async function registerPasskey(cfg = {}) {
    const optionsUrl = cfg.optionsUrl || "/webauthn/register/options";
    const verifyUrl = cfg.verifyUrl || "/webauthn/register/verify";
    try {
        const optRes = await fetch(optionsUrl, { method: 'POST', credentials: 'include' });
        if (!optRes.ok) {
            throw new Error('options failed');
        }
        const opts = await optRes.json();

        // Rehydrate binary fields
        opts.challenge = b64urlToBuffer(opts.challenge);
        if (opts.user && opts.user.id) {
            opts.user.id = b64urlToBuffer(opts.user.id);
        }
        if (Array.isArray(opts.excludeCredentials)) {
            opts.excludeCredentials = opts.excludeCredentials.map(x => ({ ...x, id: b64urlToBuffer(x.id) }));
        }

        // Experimental PRF
        const prfEnabled = !!(cfg.prf && cfg.prf.enabled);
        if (prfEnabled && opts.extensions && opts.extensions.prf && opts.extensions.prf.eval && opts.extensions.prf.eval.first) {
            opts.extensions = Object.assign({}, opts.extensions, {
                prf: { eval: { first: b64urlToBuffer(opts.extensions.prf.eval.first) } }
            });
        } else if (!prfEnabled && opts.extensions && 'prf' in opts.extensions) {
            const { prf: _prf, ...others } = opts.extensions;
            opts.extensions = others;
        }

        // Create credential
        const cred = await navigator.credentials.create({ publicKey: opts });
        if (!cred) {
            throw new Error('user canceled');
        }

        // Send back for verification/storage
        const payload = { credential: credToJSON(cred) };
        const verifyRes = await fetch(verifyUrl, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const j = await verifyRes.json().catch(() => ({ ok: false, err: 'Invalid verify response' }));
        if (!verifyRes.ok || !j.ok) {
            throw new Error(j.err || 'verify failed');
        }
        return verifiedResult(j, cred, prfEnabled);
    } catch (e) {
        console.error(e);
        return { ok: false, err: e && e.message ? e.message : String(e) };
    }
}

/**
 * Perform a passkey login (WebAuthn assertion).
 * @param {Object} cfg
 * @param {string} cfg.optionsUrl - URL to request assertion options.
 * @param {string} cfg.verifyUrl - URL to post the assertion for verification.
 * @param {{enabled: boolean}} [cfg.prf] - Request the PRF output; it is returned, never posted.
 * @returns {Promise<{ok: boolean, err?: string, prf?: {first: string, second?: string}}>} on success, the
 *          server's verification JSON with ok true, plus the PRF output in base64url when requested and returned.
 */
export async function passkeyLogin(cfg = {}) {
    const optionsUrl = cfg.optionsUrl || "/webauthn/login/options";
    const verifyUrl = cfg.verifyUrl || "/webauthn/login/verify";

    try {
        const optRes = await fetch(optionsUrl, { method: "POST", credentials: "include" });
        if (!optRes.ok) {
            throw new Error("Failed to get options");
        }
        const options = await optRes.json();
        const publicKey = Object.assign({}, options, {
            challenge: b64urlToBuffer(options.challenge),
        });
        if (publicKey.allowCredentials && publicKey.allowCredentials.length) {
            publicKey.allowCredentials = publicKey.allowCredentials.map((d) => ({
                type: d.type,
                id: b64urlToBuffer(d.id),
                transports: d.transports || undefined,
            }));
        }
        // Experimental PRF
        const prfEnabled = !!(cfg.prf && cfg.prf.enabled);
        if (
            prfEnabled &&
            publicKey.extensions &&
            publicKey.extensions.prf &&
            publicKey.extensions.prf.eval &&
            publicKey.extensions.prf.eval.first
        ) {
            publicKey.extensions = Object.assign({}, publicKey.extensions, {
                prf: { eval: { first: b64urlToBuffer(publicKey.extensions.prf.eval.first) } }
            });
        } else if (!prfEnabled && publicKey.extensions && 'prf' in publicKey.extensions) {
            const { prf: _prf, ...others } = publicKey.extensions;
            publicKey.extensions = others;
        }
        const cred = await navigator.credentials.get({ publicKey });
        const credential = {
            id: cred.id,
            type: cred.type,
            rawId: bufferToB64url(cred.rawId),
            response: {
                authenticatorData: bufferToB64url(cred.response.authenticatorData),
                clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
                signature: bufferToB64url(cred.response.signature),
                userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : null,
            },
        };

        const verifyRes = await fetch(verifyUrl, {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ credential }),
        });

        const verify = await verifyRes.json().catch(() => ({ ok: false, err: "Invalid verify response" }));
        if (!verifyRes.ok || !verify.ok) {
            throw new Error(verify.err || "Verification failed");
        }
        return verifiedResult(verify, cred, prfEnabled);
    } catch (e) {
        console.error(e);
        return { ok: false, err: e && e.message ? e.message : String(e) };
    }
}

/**
 * Bind click handler to a button for passkey registration with configurable endpoints.
 * @param {Object} cfg
 * @param {string} [cfg.buttonSelector="#createPasskeyBtn"] - Selector for the register button.
 * @param {string} [cfg.optionsUrl="/webauthn/register/options"] - Options endpoint.
 * @param {string} [cfg.verifyUrl="/webauthn/register/verify"] - Verify endpoint.
 * @param {(result: {ok: true, prf?: {first: string, second?: string}}) => void} [cfg.onSuccess] - Callback on
 *        success, with the result registerPasskey() returns.
 * @param {(error: string) => void} [cfg.onError] - Callback on failure.
 */
export function initPasskeyRegistration(cfg = {}) {
    const buttonSelector = cfg.buttonSelector || '#createPasskeyBtn';
    const optionsUrl = cfg.optionsUrl || '/webauthn/register/options';
    const verifyUrl = cfg.verifyUrl || '/webauthn/register/verify';
    const onSuccess = typeof cfg.onSuccess === 'function' ? cfg.onSuccess : () => { };
    const onError = typeof cfg.onError === 'function' ? cfg.onError : () => { };

    const btn = document.querySelector(buttonSelector);
    if (!btn) return;

    btn.addEventListener('click', async (ev) => {
        ev.preventDefault();
        const res = await registerPasskey({ optionsUrl, verifyUrl, prf: cfg.prf });
        if (res.ok) {
            onSuccess(res);
        } else {
            onError(res.err || 'Unknown error');
        }
    });
}

/**
 * Do an assertion ONLY to obtain PRF output (no login). Returns { credentialId, prfFirst } in base64url.
 */
export async function prfEvaluate(cfg = {}) {
    const optionsUrl = cfg.optionsUrl || "/webauthn/prf/options";

    const optRes = await fetch(optionsUrl, { method: "POST", credentials: "include" });
    if (!optRes.ok) throw new Error("Failed to get PRF options");

    const options = await optRes.json();

    const publicKey = Object.assign({}, options, {
        challenge: b64urlToBuffer(options.challenge),
    });

    if (publicKey.allowCredentials && publicKey.allowCredentials.length) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((d) => ({
            type: d.type,
            id: b64urlToBuffer(d.id),
            transports: d.transports || undefined,
        }));
    }

    // PRF eval (must be ArrayBuffer in request)
    if (
        publicKey.extensions &&
        publicKey.extensions.prf &&
        publicKey.extensions.prf.eval &&
        publicKey.extensions.prf.eval.first
    ) {
        publicKey.extensions = Object.assign({}, publicKey.extensions, {
            prf: { eval: { first: b64urlToBuffer(publicKey.extensions.prf.eval.first) } }
        });
    }

    const cred = await navigator.credentials.get({ publicKey });
    if (!cred) throw new Error("User canceled");

    const prf = encodePrfResultsFromCredential(cred);
    if (!prf || !prf.first) throw new Error("PRF result missing (device/browser may not support PRF)");

    return {
        credentialId: bufferToB64url(cred.rawId),
        prfFirst: prf.first,
    };
}

/**
 * Derives the 32-byte seed of a PRF output in the browser: HKDF-SHA256 with the passkey's prf_salt as
 * salt and "seed:v1" as info. For the same PRF output and salt bytes it returns the seed the server
 * derived before 3.0.0, so data encrypted under that seed stays readable.
 * @param {string} prfFirstB64Url - The PRF output (prf.first), base64url; it must be 32 bytes.
 * @param {string} saltB64Url - The passkey's prf_salt bytes, base64url.
 * @returns {Promise<string>} the seed, base64url.
 */
export async function derivePrfSeed(prfFirstB64Url, saltB64Url) {
    if (typeof prfFirstB64Url !== "string" || typeof saltB64Url !== "string") throw new TypeError("derivePrfSeed takes two base64url strings");
    const prf = new Uint8Array(b64urlToBuffer(prfFirstB64Url));
    if (prf.length !== 32) {
        throw new Error("The PRF output must be 32 bytes");
    }
    const salt = new Uint8Array(b64urlToBuffer(saltB64Url));
    if (salt.length === 0) {
        throw new Error("The PRF salt is missing");
    }
    const key = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveBits"]);
    const seed = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("seed:v1") },
        key,
        256
    );
    return bufferToB64url(seed);
}

/**
 * Bind click handler to a button for passkey login with configurable endpoints.
 * @param {Object} cfg
 * @param {string} [cfg.buttonSelector="#btn-passkey-login"] - Selector for the login button.
 * @param {string} [cfg.optionsUrl="/webauthn/login/options"] - Options endpoint.
 * @param {string} [cfg.verifyUrl="/webauthn/login/verify"] - Verify endpoint.
 * @param {(result: {ok: true, prf?: {first: string, second?: string}}) => void} [cfg.onSuccess] - Callback on
 *        success, with the result passkeyLogin() returns.
 * @param {(error: string) => void} [cfg.onError] - Callback on failure.
 */
export function initPasskeyLogin(cfg = {}) {
    const buttonSelector = cfg.buttonSelector || "#btn-passkey-login";
    const optionsUrl = cfg.optionsUrl || "/webauthn/login/options";
    const verifyUrl = cfg.verifyUrl || "/webauthn/login/verify";
    const onSuccess = typeof cfg.onSuccess === 'function' ? cfg.onSuccess : () => { };
    const onError = typeof cfg.onError === 'function' ? cfg.onError : () => { };

    const btn = document.querySelector(buttonSelector);
    if (!btn) return;
    btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const res = await passkeyLogin({ optionsUrl, verifyUrl, prf: cfg.prf });
        if (res.ok) {
            onSuccess(res);
        } else {
            onError(res.err || "Unknown error");
        }
    });
}

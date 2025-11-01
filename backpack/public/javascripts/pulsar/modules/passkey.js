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
        const prf = ext && ext.prfResults && ext.prfResults.results ? ext.prfResults.results : null;
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
        clientExtensionResults: typeof c.getClientExtensionResults === 'function' ? c.getClientExtensionResults() : {},
    };
}

/**
 * Perform a passkey registration (WebAuthn create/attestation).
 * @param {Object} cfg
 * @param {string} [cfg.optionsUrl="/webauthn/register/options"] - Creation options endpoint.
 * @param {string} [cfg.verifyUrl="/webauthn/register/verify"] - Verification endpoint.
 * @returns {Promise<{ok: boolean, err?: string}>}
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
        }

        // Create credential
        const cred = await navigator.credentials.create({ publicKey: opts });
        if (!cred) {
            throw new Error('user canceled');
        }

        // Send back for verification/storage
        const payload = { credential: credToJSON(cred) };
        if (prfEnabled) {
            const prf = encodePrfResultsFromCredential(cred);
            if (prf) {
                payload.credential.clientExtensionResults = Object.assign({}, payload.credential.clientExtensionResults || {}, { prfResults: { results: prf } });
            }
        }
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
        return { ok: true };
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
 * @returns {Promise<{ok: boolean, err?: string}>}
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
        if (prfEnabled && options.extensions && options.extensions.prf && options.extensions.prf.eval && options.extensions.prf.eval.first) {
            publicKey.extensions = Object.assign({}, publicKey.extensions || {}, {
                prf: { eval: { first: b64urlToBuffer(options.extensions.prf.eval.first) } }
            });
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
            clientExtensionResults: prfEnabled ? (function () { const prf = encodePrfResultsFromCredential(cred); return prf ? { prfResults: { results: prf } } : {}; })() : undefined,
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
        return { ok: true };
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
 * @param {(result: {ok: boolean, err?: string}) => void} [cfg.onSuccess] - Callback on success.
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
 * Bind click handler to a button for passkey login with configurable endpoints.
 * @param {Object} cfg
 * @param {string} [cfg.buttonSelector="#btn-passkey-login"] - Selector for the login button.
 * @param {string} [cfg.optionsUrl="/webauthn/login/options"] - Options endpoint.
 * @param {string} [cfg.verifyUrl="/webauthn/login/verify"] - Verify endpoint.
 * @param {(result: {ok: boolean, err?: string}) => void} [cfg.onSuccess] - Callback on success.
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

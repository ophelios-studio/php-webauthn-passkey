/*
  The PRF output of a passkey is key material for the browser alone: the module hands it to its caller
  and never posts it. Each ceremony runs against a fake fetch and a fake navigator.credentials whose
  authenticator returns known PRF bytes, and every body the module posts is searched for them.

  Run with: node --test tests/js (no dependency). The module is loaded through a data: URL, as the
  repository has no package.json declaring a module type.
*/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const SOURCE = readFileSync(new URL('../../backpack/public/javascripts/pulsar/modules/passkey.js', import.meta.url), 'utf8');
const loadModule = () => import('data:text/javascript;base64,' + Buffer.from(SOURCE).toString('base64'));

const PRF_FIRST = Uint8Array.from({ length: 32 }, (_, i) => (0xa5 + 7 * i) & 0xff);
const PRF_SECOND = Uint8Array.from({ length: 32 }, (_, i) => (0x3c + 11 * i) & 0xff);
const PRF_INPUT = 'FJWCwMX44iSjMrLnca4yFZJEilp41nO18uF3S6FoLIA';
const PRF_SALT = '4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8';

const bytes = (text) => new TextEncoder().encode(text).buffer;
const base64 = (u8) => Buffer.from(u8).toString('base64');
const base64Url = (u8) => Buffer.from(u8).toString('base64url');
const hex = (u8) => Buffer.from(u8).toString('hex');

/** Every way a body could carry these bytes: base64url, base64, hex, and a byte array or Uint8Array as JSON. */
function encodingsOf(u8) {
  return [
    base64Url(u8),
    base64(u8).replace(/=+$/, ''),
    hex(u8),
    JSON.stringify(Array.from(u8)).slice(1, -1),
    JSON.stringify(u8).slice(1, -1),
  ];
}

function keysOf(value, found = []) {
  if (value && typeof value === 'object') {
    for (const [key, inner] of Object.entries(value)) {
      found.push(key);
      keysOf(inner, found);
    }
  }
  return found;
}

/**
 * A credential whose authenticator returned the known PRF output, as an ArrayBuffer (what browsers
 * give) or a Uint8Array, under prf.results (the standard key) or prfResults.results (the older one).
 */
function fakeCredential(ceremony, kind, location) {
  const bytesOf = (u8) => (kind === 'ArrayBuffer' ? u8.slice().buffer : u8.slice());
  const results = { first: bytesOf(PRF_FIRST), second: bytesOf(PRF_SECOND) };
  const extensions = { credProps: { rk: true } };
  if (location === 'prf.results') {
    extensions.prf = { enabled: true, results };
  } else {
    extensions.prfResults = { results };
  }
  const response = ceremony === 'registration'
    ? { clientDataJSON: bytes('{}'), attestationObject: bytes('att'), getTransports: () => ['internal'] }
    : { clientDataJSON: bytes('{}'), authenticatorData: bytes('auth'), signature: bytes('sig'), userHandle: bytes('user') };
  return { id: 'abc', type: 'public-key', rawId: bytes('raw'), response, getClientExtensionResults: () => extensions };
}

/** Swaps fetch, navigator and document for doubles while run() executes, and restores them. */
async function withDoubles(doubles, run) {
  const saved = ['fetch', 'navigator', 'document'].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]);
  for (const [name, value] of Object.entries(doubles)) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
  try {
    return await run();
  } finally {
    for (const [name, descriptor] of saved) {
      if (descriptor) {
        Object.defineProperty(globalThis, name, descriptor);
      } else {
        delete globalThis[name];
      }
    }
  }
}

/**
 * Doubles for one ceremony: the options endpoint asks for a PRF evaluation, the verify endpoint
 * answers with the passkey's prf_salt. Every request is captured with its body.
 */
function ceremonyDoubles(ceremony, kind, location) {
  const calls = [];
  const options = ceremony === 'registration'
    ? { challenge: 'AAAA', user: { id: 'AQID' }, extensions: { prf: { eval: { first: PRF_INPUT } } } }
    : { challenge: 'AAAA', extensions: { prf: { eval: { first: PRF_INPUT } } } };
  const fetch = async (url, init) => {
    calls.push({ url, body: init && init.body });
    const json = calls.length === 1 ? options : { ok: true, prf_salt: PRF_SALT };
    return { ok: true, json: async () => json };
  };
  const answer = async () => fakeCredential(ceremony, kind, location);
  const navigator = { credentials: { create: answer, get: answer } };
  return { calls, doubles: { fetch, navigator } };
}

function assertNoPrfOutputPosted(calls) {
  for (const { url, body } of calls) {
    if (body === undefined) {
      continue;
    }
    for (const encoded of [...encodingsOf(PRF_FIRST), ...encodingsOf(PRF_SECOND)]) {
      assert.equal(body.toLowerCase().includes(encoded.toLowerCase()), false, `${url} posted the PRF output (${encoded})`);
    }
    const keys = keysOf(JSON.parse(body));
    assert.equal(keys.includes('prf'), false, `${url} posted a prf key`);
    assert.equal(keys.includes('prfResults'), false, `${url} posted a prfResults key`);
  }
}

const RUNS = { registration: 'registerPasskey', login: 'passkeyLogin' };

for (const ceremony of Object.keys(RUNS)) {
  for (const prfEnabled of [true, false]) {
    for (const kind of ['ArrayBuffer', 'Uint8Array']) {
      for (const location of ['prf.results', 'prfResults.results']) {
        const name = `${ceremony}, cfg.prf ${prfEnabled ? 'enabled' : 'absent'}, ${kind} under ${location}`;

        test(`${name}: no body carries the PRF output`, async () => {
          const { calls, doubles } = ceremonyDoubles(ceremony, kind, location);
          const cfg = { optionsUrl: '/o', verifyUrl: '/v', prf: prfEnabled ? { enabled: true } : undefined };

          const result = await withDoubles(doubles, async () => (await loadModule())[RUNS[ceremony]](cfg));

          assert.equal(result.ok, true, result.err);
          assert.equal(calls.length, 2);
          assert.equal(calls[1].url, '/v');
          assertNoPrfOutputPosted(calls);
        });

        test(`${name}: the result carries the server JSON, and the PRF output only when requested`, async () => {
          const { doubles } = ceremonyDoubles(ceremony, kind, location);
          const cfg = { optionsUrl: '/o', verifyUrl: '/v', prf: prfEnabled ? { enabled: true } : undefined };

          const result = await withDoubles(doubles, async () => (await loadModule())[RUNS[ceremony]](cfg));

          assert.equal(result.prf_salt, PRF_SALT);
          assert.deepEqual(result.prf, prfEnabled ? { first: base64Url(PRF_FIRST), second: base64Url(PRF_SECOND) } : undefined);
        });
      }
    }
  }
}

test('registration still posts every client extension result but the PRF ones', async () => {
  const { calls, doubles } = ceremonyDoubles('registration', 'ArrayBuffer', 'prf.results');

  await withDoubles(doubles, async () => (await loadModule()).registerPasskey({ optionsUrl: '/o', verifyUrl: '/v', prf: { enabled: true } }));

  assert.deepEqual(JSON.parse(calls[1].body).credential.clientExtensionResults, { credProps: { rk: true } });
});

for (const [init, ceremony] of [['initPasskeyRegistration', 'registration'], ['initPasskeyLogin', 'login']]) {
  test(`${init} hands onSuccess the whole result, PRF output included`, async () => {
    const { doubles } = ceremonyDoubles(ceremony, 'ArrayBuffer', 'prf.results');
    let click = null;
    const button = { addEventListener: (type, handler) => { click = handler; } };
    doubles.document = { querySelector: () => button };
    let received = null;

    await withDoubles(doubles, async () => {
      (await loadModule())[init]({ prf: { enabled: true }, onSuccess: (result) => { received = result; } });
      await click({ preventDefault: () => {} });
    });

    assert.equal(received.prf_salt, PRF_SALT);
    assert.equal(received.prf.first, base64Url(PRF_FIRST));
  });
}

test('prfEvaluate returns the PRF output and posts nothing but the options request', async () => {
  const { calls, doubles } = ceremonyDoubles('login', 'ArrayBuffer', 'prf.results');

  const result = await withDoubles(doubles, async () => (await loadModule()).prfEvaluate({ optionsUrl: '/o' }));

  assert.deepEqual(result, { credentialId: base64Url(new Uint8Array(bytes('raw'))), prfFirst: base64Url(PRF_FIRST) });
  assert.deepEqual(calls, [{ url: '/o', body: undefined }]);
});

test('runPrfBoundAction is no longer exported', async () => {
  const exported = Object.keys(await loadModule());

  assert.equal(exported.includes('runPrfBoundAction'), false);
  assert.equal(exported.includes('prfEvaluate'), true);
});

/*
  Expected seeds computed once in PHP by the 2.0.0 server derivation, hash_hkdf('sha256', $prf, 32,
  'seed:v1', $salt) as PasskeyService::deriveSeedFromPrf() ran it: the first row by PHP 8.4 on
  2026-11-24 (it matched deriveSeedFromPrf() at tag 2.0.0), the second is the seed tests/PrfSeedTest.php
  pinned in 2.0.0.
*/
const SEED_VECTORS = [
  ['bytes 0x00..0x1f, salt 0xe0..0xff', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', PRF_SALT, 'FV5KL7nSygHHiAK60QHyxtwpnED3HZNWV4u98nFx4AQ'],
  ['32 bytes of 0x01, salt of 32 "Z"', 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE', base64Url(Buffer.from('Z'.repeat(32))), 'h5W5K-XXFahvEPSvNobz588Osn8vgHaCLFTEg0sGJ5A'],
];

for (const [name, prf, salt, seed] of SEED_VECTORS) {
  test(`derivePrfSeed derives the seed the server derived before 3.0.0 (${name})`, async () => {
    const { derivePrfSeed } = await loadModule();

    assert.equal(await derivePrfSeed(prf, salt), seed);
  });
}

for (const [name, prf] of [['empty', ''], ['31 bytes', base64Url(PRF_FIRST.slice(1))], ['33 bytes', base64Url(Buffer.concat([PRF_FIRST, PRF_FIRST.slice(0, 1)]))]]) {
  test(`derivePrfSeed refuses a PRF output that is not 32 bytes (${name})`, async () => {
    const { derivePrfSeed } = await loadModule();

    await assert.rejects(derivePrfSeed(prf, PRF_SALT));
  });
}

test('derivePrfSeed refuses a missing salt', async () => {
  const { derivePrfSeed } = await loadModule();

  await assert.rejects(derivePrfSeed(base64Url(PRF_FIRST), ''));
});

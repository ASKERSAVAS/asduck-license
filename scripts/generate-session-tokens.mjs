import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const registryPath = process.env.ASDUCK_SESSION_REGISTRY || 'session_registry.json';
const outRoot = process.env.ASDUCK_PAGES_OUT || '_site';
const privateB64 = (process.env.ASDUCK_SESSION_PRIVATE_KEY_B64 || '').trim();
const expectedPublicPath = process.env.ASDUCK_SESSION_PUBLIC_KEY || 'session_public_key.b64';

if (!privateB64) throw new Error('ASDUCK_SESSION_PRIVATE_KEY_B64 secret missing');
if (!fs.existsSync(registryPath)) throw new Error(`Registry missing: ${registryPath}`);
if (!fs.existsSync(expectedPublicPath)) throw new Error(`Session public key anchor missing: ${expectedPublicPath}`);

const registryBytes = fs.readFileSync(registryPath);
const registry = JSON.parse(registryBytes.toString('utf8'));
const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9A-F]+$/.test(s);

if (registry.V !== 2 ||
    !Array.isArray(registry.R) ||
    registry.R.length < 1 ||
    registry.R.length > 2 ||
    !registry.R.every(x => isHex(x, 32)) ||
    !isHex(registry.T, 32) ||
    !Array.isArray(registry.E)) {
  throw new Error('Invalid session_registry.json V2 schema');
}

const privateKey = crypto.createPrivateKey({
  key: Buffer.from(privateB64, 'base64'),
  format: 'der',
  type: 'pkcs8'
});

if (privateKey.asymmetricKeyType !== 'ec' ||
    privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
  throw new Error('Session signer must be EC P-256');
}

const expectedPublicB64 = fs.readFileSync(expectedPublicPath, 'utf8').trim();
const derivedPublicB64 = crypto.createPublicKey(privateKey).export({
  format: 'der',
  type: 'spki'
}).toString('base64');
if (!expectedPublicB64 || expectedPublicB64 !== derivedPublicB64) {
  throw new Error('GitHub session signer secret does not match committed session public key');
}

fs.rmSync(outRoot, { recursive: true, force: true });
fs.mkdirSync(path.join(outRoot, 'sessions'), { recursive: true });

for (const name of ['revoked.json', 'security.json', 'update.json', 'CNAME']) {
  if (fs.existsSync(name)) {
    fs.copyFileSync(name, path.join(outRoot, name));
  }
}

fs.writeFileSync(path.join(outRoot, '.nojekyll'), '');
fs.writeFileSync(
  path.join(outRoot, 'index.html'),
  '<!doctype html><meta charset="utf-8"><title>ASDUCK Security Service</title>');

const security = JSON.parse(fs.readFileSync('security.json', 'utf8'));
const revoked = JSON.parse(fs.readFileSync('revoked.json', 'utf8'));
if (!Number.isSafeInteger(security.X) || !Number.isSafeInteger(revoked.X) ||
    security.X <= 0 || revoked.X <= 0) {
  throw new Error('Signed security/revocation expiry is invalid');
}

const now = Math.floor(Date.now() / 1000);
const primaryMaxExpiry = now + 45 * 60;
const stableMaxExpiry = Math.min(
  now + 36 * 24 * 60 * 60,
  security.X,
  revoked.X);
const sequence = Math.floor(now / 300);
let written = 0;
let stableWritten = 0;

function sign(entry, build, channel, expiryLimit) {
  const expires = Math.min(expiryLimit, entry.X);
  if (expires <= now) return null;

  const canonical =
    'ASDUCK-SESSION-V2\n' +
    'V=2\n' +
    `T=${entry.T}\n` +
    `D=${entry.D}\n` +
    `B=${build}\n` +
    `C=${channel}\n` +
    `I=${now}\n` +
    `E=${expires}\n` +
    `Q=${sequence}\n`;

  const signature = crypto.sign(
    'sha256',
    Buffer.from(canonical, 'utf8'),
    { key: privateKey, dsaEncoding: 'ieee-p1363' });

  if (signature.length !== 64)
    throw new Error('Unexpected P-256 signature length');

  return {
    V: 2,
    T: entry.T,
    D: entry.D,
    B: build,
    C: channel,
    I: now,
    E: expires,
    Q: sequence,
    S: signature.toString('base64url')
  };
}

for (const entry of registry.E) {
  if (!entry ||
      !isHex(entry.T, 64) ||
      !(entry.D === '*' || isHex(entry.D, 64)) ||
      !Number.isSafeInteger(entry.X) ||
      entry.X <= 0) {
    throw new Error('Malformed session registry entry');
  }

  // Expired licenses are simply omitted from the next Pages generation.
  // This keeps the scheduled workflow healthy even if the owner has not
  // republished the registry since a license naturally expired.
  if (entry.X <= now + 30) {
    continue;
  }

  for (const build of registry.R) {
    const token = sign(entry, build, 'release', primaryMaxExpiry);
    if (!token) continue;
    const dir = path.join(outRoot, 'sessions', 'release', build);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, `${entry.T}.json`),
      JSON.stringify(token, null, 2) + '\n');
    written++;

    const stableToken = sign(entry, build, 'release', stableMaxExpiry);
    if (stableToken) {
      const stableDir = path.join(outRoot, 'sessions-stable', 'release', build);
      fs.mkdirSync(stableDir, { recursive: true });
      fs.writeFileSync(
        path.join(stableDir, `${entry.T}.json`),
        JSON.stringify(stableToken, null, 2) + '\n');
      stableWritten++;
    }
  }

  const testToken = sign(entry, registry.T, 'test', primaryMaxExpiry);
  if (testToken) {
    const dir = path.join(outRoot, 'sessions', 'test', registry.T);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, `${entry.T}.json`),
      JSON.stringify(testToken, null, 2) + '\n');
    written++;
  }

  const stableTestToken = sign(entry, registry.T, 'test', stableMaxExpiry);
  if (stableTestToken) {
    const stableDir = path.join(outRoot, 'sessions-stable', 'test', registry.T);
    fs.mkdirSync(stableDir, { recursive: true });
    fs.writeFileSync(
      path.join(stableDir, `${entry.T}.json`),
      JSON.stringify(stableTestToken, null, 2) + '\n');
    stableWritten++;
  }
}

console.log(
  `ASDUCK signed session tokens generated: primary=${written}; stable=${stableWritten}; ` +
  `licenses=${registry.E.length}; releaseBuilds=${registry.R.length}`);

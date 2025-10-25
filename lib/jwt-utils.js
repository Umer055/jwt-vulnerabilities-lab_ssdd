const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

const HS_SECRET = process.env.JWT_HS_SECRET || fs.readFileSync(path.join(__dirname, '..', 'keys', '698dc19d489c4e4db73e28a713eab07b'), 'utf-8');

function extractBearerToken(req) {
    const auth = req.headers['authorization'] || '';
    const m = auth.match(/^Bearer\s+(.*)$/i);
    if(!m) return null;
    return m[1].trim();
}

function ensureAlgNotNone(header) {
    if(!header || !header.alg) return false;
    return header.alg.toLowerCase() !== 'none';
}

function verifyHsToken(token, key) {
    return jwt.verify(token, key, { algorithms: ['HS256'] });
}

function verifyRsToken(token, publicKey) {
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

async function fetchJwksPem(jku, expectedKid, whitelist=[]) {
    if(!jku) throw new Error('missing jku');
    if(whitelist.length && !whitelist.includes(jku)) throw new Error('jku not allowed');

    const res = await fetch(jku);
    if(!res.ok) throw new Error('failed to fetch jwks');
    const jwks = await res.json();
    if(!Array.isArray(jwks)) throw new Error('invalid jwks format');

    let jwk = null;
    if(expectedKid) jwk = jwks.find(k => k.kid === expectedKid);
    if(!jwk) jwk = jwks[0];
    if(!jwk || jwk.kty !== 'RSA') throw new Error('no suitable jwk');

    return jwkToPem(jwk);
}

module.exports = {
    extractBearerToken,
    ensureAlgNotNone,
    verifyHsToken,
    verifyRsToken,
    fetchJwksPem,
    HS_SECRET
};

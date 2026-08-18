const crypto = require('crypto');
const db = require('./db');

const RP_NAME = '极风工作室';
const RP_ID = (() => {
  const u = process.env.URL || 'https://jifeng-studio.netlify.app';
  try { return new URL(u).hostname; } catch(e) { return 'jifeng-studio.netlify.app'; }
})();
const ORIGIN = process.env.URL || 'https://jifeng-studio.netlify.app';

function randomBuf(len) { return crypto.randomBytes(len); }
function bufToB64(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return bytes.toString('base64url');
}
function b64ToBuf(b64) { return Buffer.from(b64, 'base64url'); }

// CBOR minimal decoder (only what we need for attestation object)
function decodeCBOR(buf, offset) {
  offset = offset || 0;
  const initialByte = buf[offset];
  const majorType = initialByte >> 5;
  const additionalInfo = initialByte & 0x1f;
  let val, length, newOffset = offset + 1;

  if (additionalInfo < 24) { val = additionalInfo; }
  else if (additionalInfo === 24) { val = buf[newOffset]; newOffset += 1; }
  else if (additionalInfo === 25) { val = buf.readUInt16BE(newOffset); newOffset += 2; }
  else if (additionalInfo === 26) { val = buf.readUInt32BE(newOffset); newOffset += 4; }
  else if (additionalInfo === 27) {
    val = Number(buf.readBigUInt64BE(newOffset)); newOffset += 8;
  }

  if (majorType === 0) return { value: val, offset: newOffset };
  if (majorType === 1) return { value: -1 - val, offset: newOffset };
  if (majorType === 2 || majorType === 3) {
    const len = val;
    const data = buf.slice(newOffset, newOffset + len);
    return { value: data, offset: newOffset + len };
  }
  if (majorType === 5) {
    const obj = {};
    for (let i = 0; i < val; i++) {
      const keyRes = decodeCBOR(buf, newOffset);
      const key = keyRes.value.toString ? keyRes.value.toString() : String(keyRes.value);
      newOffset = keyRes.offset;
      const valRes = decodeCBOR(buf, newOffset);
      obj[key] = valRes.value;
      newOffset = valRes.offset;
    }
    return { value: obj, offset: newOffset };
  }
  if (majorType === 4) {
    const arr = [];
    for (let i = 0; i < val; i++) {
      const res = decodeCBOR(buf, newOffset);
      arr.push(res.value);
      newOffset = res.offset;
    }
    return { value: arr, offset: newOffset };
  }
  if (majorType === 7) {
    if (additionalInfo === 20) return { value: false, offset: newOffset };
    if (additionalInfo === 21) return { value: true, offset: newOffset };
    if (additionalInfo === 22) return { value: null, offset: newOffset };
    if (additionalInfo === 23) return { value: undefined, offset: newOffset };
    if (additionalInfo >= 25 && additionalInfo <= 27) {
      const len = additionalInfo === 25 ? 2 : additionalInfo === 26 ? 4 : 8;
      const data = buf.slice(newOffset, newOffset + len);
      return { value: data, offset: newOffset + len };
    }
  }
  throw new Error('Unsupported CBOR type: ' + majorType + ' at offset ' + offset);
}

// Convert COSE ES256 key to SPKI PEM
function coseToSPKI(coseKey) {
  // COSE key map for ES256: kty=1:2, alg=3:-7, crv=-1:1, x=-2, y=-3
  const x = coseKey['-2'];
  const y = coseKey['-3'];
  if (!x || !y) throw new Error('Invalid COSE key');

  // SPKI prefix for P-256 EC public key
  const prefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const keyBuf = Buffer.concat([prefix, Buffer.from(x), Buffer.from(y)]);
  return '-----BEGIN PUBLIC KEY-----\n' + keyBuf.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----';
}

async function getRegOptions() {
  const cred = await db.get('webauthn:credential');
  const excludeCredentials = [];
  if (cred && cred.credentialID) {
    excludeCredentials.push({
      id: bufToB64(b64ToBuf(cred.credentialID)),
      type: 'public-key',
      transports: cred.transports || ['internal']
    });
  }
  const challenge = bufToB64(randomBuf(32));
  await db.set('webauthn:challenge:reg', challenge, 5 * 60);
  return {
    challenge: b64ToBuf(challenge),
    rp: { name: RP_NAME, id: RP_ID },
    user: {
      id: b64ToBuf(bufToB64(Buffer.from('nuoyan-admin'))),
      name: 'NUOYAN',
      displayName: '极风管理员'
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 }
    ],
    timeout: 60000,
    attestation: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
      authenticatorAttachment: 'platform'
    }
  };
}

async function verifyReg(body) {
  const challenge = await db.get('webauthn:challenge:reg');
  if (!challenge) return { ok: false, error: '挑战已过期' };

  try {
    const clientDataJSON = b64ToBuf(body.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    if (clientData.type !== 'webauthn.create') return { ok: false, error: '类型错误' };
    if (clientData.challenge !== challenge) return { ok: false, error: '挑战不匹配' };
    if (clientData.origin !== ORIGIN) return { ok: false, error: '来源不匹配' };

    const attestationBuf = b64ToBuf(body.response.attestationObject);
    const attestation = decodeCBOR(attestationBuf).value;
    const authData = Buffer.from(attestation.authData);

    // Parse authenticator data
    const rpIdHash = authData.slice(0, 32);
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);

    // Verify RP ID hash
    const expectedRpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
    if (!rpIdHash.equals(expectedRpIdHash)) return { ok: false, error: 'RP ID不匹配' };

    // Check user present and verified
    if (!(flags & 0x01)) return { ok: false, error: '用户未确认' };
    if (!(flags & 0x04)) return { ok: false, error: '需要用户验证' };

    // Parse attested credential data
    let offset = 37;
    const aaguid = authData.slice(offset, offset + 16);
    offset += 16;
    const credIdLen = authData.readUInt16BE(offset);
    offset += 2;
    const credentialID = authData.slice(offset, offset + credIdLen);
    offset += credIdLen;

    // Parse COSE public key
    const coseRes = decodeCBOR(authData, offset);
    const coseKey = coseRes.value;

    // Convert to SPKI and verify it works
    const pubKeyPEM = coseToSPKI(coseKey);

    const credential = {
      credentialID: bufToB64(credentialID),
      publicKeyPEM: pubKeyPEM,
      counter: signCount,
      transports: body.response.transports || ['internal'],
      registeredAt: Date.now()
    };
    await db.set('webauthn:credential', credential);
    await db.del('webauthn:challenge:reg');
    return { ok: true };
  } catch(e) {
    return { ok: false, error: e.message };
  }
}

async function getLoginOptions() {
  const cred = await db.get('webauthn:credential');
  if (!cred || !cred.credentialID) return { ok: false, error: '尚未注册生物识别' };
  const challenge = bufToB64(randomBuf(32));
  await db.set('webauthn:challenge:login', challenge, 5 * 60);
  return {
    ok: true,
    options: {
      challenge: b64ToBuf(challenge),
      rpId: RP_ID,
      timeout: 60000,
      userVerification: 'required',
      allowCredentials: [{
        id: b64ToBuf(cred.credentialID),
        type: 'public-key',
        transports: cred.transports || ['internal']
      }]
    }
  };
}

async function verifyLogin(body) {
  const challenge = await db.get('webauthn:challenge:login');
  if (!challenge) return { ok: false, error: '挑战已过期' };
  const cred = await db.get('webauthn:credential');
  if (!cred) return { ok: false, error: '未注册' };

  try {
    const clientDataJSON = b64ToBuf(body.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON.toString());

    if (clientData.type !== 'webauthn.get') return { ok: false, error: '类型错误' };
    if (clientData.challenge !== challenge) return { ok: false, error: '挑战不匹配' };
    if (clientData.origin !== ORIGIN) return { ok: false, error: '来源不匹配' };

    const authenticatorData = b64ToBuf(body.response.authenticatorData);
    const signature = b64ToBuf(body.response.signature);

    // Verify RP ID hash
    const rpIdHash = authenticatorData.slice(0, 32);
    const expectedRpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
    if (!rpIdHash.equals(expectedRpIdHash)) return { ok: false, error: 'RP ID不匹配' };

    const flags = authenticatorData[32];
    if (!(flags & 0x01)) return { ok: false, error: '用户未确认' };
    if (!(flags & 0x04)) return { ok: false, error: '需要用户验证' };

    // Verify signature: SHA256(authData + SHA256(clientDataJSON))
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    const verifier = crypto.createVerify('SHA256');
    verifier.update(signedData);
    const valid = verifier.verify(cred.publicKeyPEM, signature);

    if (!valid) return { ok: false, error: '签名验证失败' };

    // Update counter
    const newCounter = authenticatorData.readUInt32BE(33);
    cred.counter = newCounter;
    await db.set('webauthn:credential', cred);
    await db.del('webauthn:challenge:login');
    return { ok: true };
  } catch(e) {
    return { ok: false, error: e.message };
  }
}

async function isRegistered() {
  const cred = await db.get('webauthn:credential');
  return !!(cred && cred.credentialID);
}

module.exports = { getRegOptions, verifyReg, getLoginOptions, verifyLogin, isRegistered };

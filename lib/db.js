const { getStore } = require('@netlify/blobs');

let _store;
function store() {
  if (!_store) _store = getStore({
    name: 'jfdb',
    siteID: process.env.SITE_ID,
    token: process.env.NETLIFY_BLOBS_TOKEN || process.env.NETLIFY_FUNCTIONS_TOKEN
  });
  return _store;
}

const PREFIX = 'jf:';

async function readVal(key) {
  try {
    const raw = await store().get(PREFIX + key);
    if (raw === null || raw === undefined) return null;
    const data = JSON.parse(raw);
    if (data.__exp && Date.now() > data.__exp) {
      await store().delete(PREFIX + key);
      return null;
    }
    return data.__v;
  } catch (e) { return null; }
}

async function writeVal(key, val, expSec) {
  const data = { __v: val };
  if (expSec) data.__exp = Date.now() + expSec * 1000;
  await store().set(PREFIX + key, JSON.stringify(data));
}

async function get(key) {
  return readVal(key);
}

async function set(key, val, exp) {
  return writeVal(key, val, exp);
}

async function del(key) {
  await store().delete(PREFIX + key);
}

async function incr(key) {
  let val = await readVal(key);
  val = (parseInt(val) || 0) + 1;
  await writeVal(key, val);
  return val;
}

async function expire(key, sec) {
  const val = await readVal(key);
  if (val !== null) await writeVal(key, val, sec);
}

async function lpush(key, val) {
  let list = await readVal(key);
  if (!Array.isArray(list)) list = [];
  list.unshift(val);
  await writeVal(key, list);
}

async function lrange(key, start, stop) {
  let list = await readVal(key);
  if (!Array.isArray(list)) return [];
  if (stop === -1) stop = list.length - 1;
  return list.slice(start, stop + 1);
}

async function ltrim(key, start, stop) {
  let list = await readVal(key);
  if (!Array.isArray(list)) return;
  if (stop === -1) stop = list.length - 1;
  await writeVal(key, list.slice(start, stop + 1));
}

async function sadd(key, val) {
  let set = await readVal(key);
  if (!Array.isArray(set)) set = [];
  if (!set.includes(val)) { set.push(val); await writeVal(key, set); }
}

async function smembers(key) {
  const set = await readVal(key);
  return Array.isArray(set) ? set : [];
}

async function sismember(key, val) {
  const set = await readVal(key);
  return Array.isArray(set) && set.includes(val);
}

async function srem(key, val) {
  let set = await readVal(key);
  if (Array.isArray(set)) {
    const filtered = set.filter(v => v !== val);
    await writeVal(key, filtered);
  }
}

async function keys(pattern) {
  const all = await store().list();
  const regex = new RegExp('^' + PREFIX + pattern.replace(/\*/g, '.*') + '$');
  return all.blobs.map(b => b.key.replace(PREFIX, '')).filter(k => regex.test(PREFIX + k));
}

async function hset(key, field, val) {
  let hash = await readVal(key);
  if (!hash || typeof hash !== 'object') hash = {};
  hash[field] = val;
  await writeVal(key, hash);
}

async function hget(key, field) {
  const hash = await readVal(key);
  return hash && typeof hash === 'object' ? hash[field] : null;
}

async function hgetall(key) {
  const hash = await readVal(key);
  return hash && typeof hash === 'object' ? hash : {};
}

module.exports = { get, set, del, incr, expire, lpush, lrange, ltrim, sadd, smembers, sismember, srem, keys, hset, hget, hgetall };

// Chiffre site.html avec le mot de passe et réécrit index.html (page d'accès) en gardant le même wrapper.
// usage : node encrypt.mjs <mot_de_passe> <site.html> <index.html>
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
const [pw, src, dst] = process.argv.slice(2);
const plain = readFileSync(src);
const salt = randomBytes(16), iv = randomBytes(12), n = 600000;
const key = pbkdf2Sync(pw, salt, n, 32, 'sha256');
const c = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
const P = { s: salt.toString('base64'), i: iv.toString('base64'), n, c: ct.toString('base64') };
let html = readFileSync(dst, 'utf8');
const re = /const P=\{[^\n]*\};/;
if (!re.test(html)) throw new Error('bloc P introuvable');
html = html.replace(re, 'const P=' + JSON.stringify(P) + ';');
writeFileSync(dst, html);
console.log('ok', plain.length, 'octets ->', ct.length);

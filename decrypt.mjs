// Déchiffre index.html -> site.html. usage : node decrypt.mjs <mot_de_passe> <index.html> <out.html>
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, createDecipheriv } from 'node:crypto';
const [pw, src, dst] = process.argv.slice(2);
const html = readFileSync(src, 'utf8');
const P = JSON.parse(html.match(/const P=(\{[^\n]*\});/)[1]);
const key = pbkdf2Sync(pw, Buffer.from(P.s, 'base64'), P.n, 32, 'sha256');
const ct = Buffer.from(P.c, 'base64');
const d = createDecipheriv('aes-256-gcm', key, Buffer.from(P.i, 'base64'));
d.setAuthTag(ct.subarray(ct.length - 16));
writeFileSync(dst, Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]));
console.log('ok');

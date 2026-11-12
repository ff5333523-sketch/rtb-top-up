const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET;
const dbPath = process.env.DATABASE_PATH || './data/rtb-topup.sqlite';

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Missing config: set ADMIN_USERNAME, ADMIN_PASSWORD_HASH and SESSION_SECRET (32+ chars).');
  process.exit(1);
}
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS packages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL,
 country TEXT NOT NULL, price INTEGER NOT NULL CHECK(price >= 0), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS offers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, player_id TEXT NOT NULL, package_name TEXT NOT NULL,
 country TEXT NOT NULL, amount INTEGER NOT NULL, customer_contact TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
db.prepare('INSERT OR IGNORE INTO admins(username) VALUES (?)').run(ADMIN_USERNAME);
const defaultSettings = {
 siteName: 'RTB TOP UP',
 whatsapp: '01344334536',
 telegram: 'https://t.me/RTBtopup',
 notice: 'Telegram চ্যানেলে যুক্ত হয়ে অফার দেখুন'
};
const setSetting = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)');
for (const [k,v] of Object.entries(defaultSettings)) setSetting.run(k, v);

const loginLimiter = rateLimit({ windowMs: 15*60*1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60*1000, limit: 90, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);

function tokenHash(token) { return crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex'); }
function setCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `rtb_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
}
function clearCookie(res) { res.setHeader('Set-Cookie', 'rtb_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); }
function auth(req,res,next) {
  const token = (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('rtb_admin='))?.slice(10);
  if (!token) return res.status(401).json({error:'লগইন প্রয়োজন'});
  const row = db.prepare('SELECT username,expires_at FROM sessions WHERE token_hash=?').get(tokenHash(token));
  if (!row || row.expires_at < Date.now()) {
    if (row) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(token));
    clearCookie(res); return res.status(401).json({error:'সেশন শেষ হয়েছে, আবার লগইন করুন'});
  }
  req.admin = row.username; next();
}
function cleanString(v,max=120) { return typeof v === 'string' ? v.trim().slice(0,max) : ''; }
function validPackage(body) {
  const name=cleanString(body.name,100), category=cleanString(body.category,40), country=cleanString(body.country,30);
  const price=Number(body.price);
  if (!name || !['Diamond','Membership','Weekly Lite','Special Offer'].includes(category) ||
      !['Bangladesh','India','Indonesia'].includes(country) || !Number.isSafeInteger(price) || price<0 || price>10000000) return null;
  return {name,category,country,price,active:body.active===false?0:1};
}

app.post('/api/admin/login', loginLimiter, async (req,res) => {
  const username=cleanString(req.body.username,80), password=typeof req.body.password==='string'?req.body.password:'';
  if (username !== ADMIN_USERNAME || !await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({error:'ইউজারনেম অথবা পাসওয়ার্ড সঠিক নয়'});
  }
  const token=crypto.randomBytes(32).toString('hex'), hash=tokenHash(token), expiry=Date.now()+8*60*60*1000;
  db.prepare('INSERT INTO sessions(token_hash,username,expires_at) VALUES (?,?,?)').run(hash,username,expiry);
  setCookie(res,token); res.json({ok:true,username});
});
app.post('/api/admin/logout', auth, (req,res) => {
  const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('rtb_admin='))?.slice(10);
  if(token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(token));
  clearCookie(res); res.json({ok:true});
});
app.get('/api/admin/me', auth, (req,res)=>res.json({username:req.admin}));
app.get('/api/admin/dashboard', auth, (req,res)=>res.json({
  packages:db.prepare('SELECT COUNT(*) n FROM packages').get().n,
  orders:db.prepare('SELECT COUNT(*) n FROM orders').get().n,
  offers:db.prepare('SELECT COUNT(*) n FROM offers').get().n,
  pending:db.prepare("SELECT COUNT(*) n FROM orders WHERE status='Pending'").get().n
}));
app.get('/api/admin/packages', auth, (req,res)=>res.json(db.prepare('SELECT * FROM packages ORDER BY id DESC').all()));
app.post('/api/admin/packages', auth, (req,res)=>{
  const p=validPackage(req.body); if(!p) return res.status(400).json({error:'প্যাকেজের তথ্য সঠিক নয়'});
  const info=db.prepare('INSERT INTO packages(name,category,country,price,active) VALUES (@name,@category,@country,@price,@active)').run(p);
  res.status(201).json({id:info.lastInsertRowid});
});
app.put('/api/admin/packages/:id', auth, (req,res)=>{
  const p=validPackage(req.body); if(!p) return res.status(400).json({error:'প্যাকেজের তথ্য সঠিক নয়'});
  const info=db.prepare('UPDATE packages SET name=@name,category=@category,country=@country,price=@price,active=@active WHERE id=@id').run({...p,id:Number(req.params.id)});
  if(!info.changes) return res.status(404).json({error:'প্যাকেজ পাওয়া যায়নি'}); res.json({ok:true});
});
app.delete('/api/admin/packages/:id', auth, (req,res)=>{db.prepare('DELETE FROM packages WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.get('/api/admin/offers', auth, (req,res)=>res.json(db.prepare('SELECT * FROM offers ORDER BY id DESC').all()));
app.post('/api/admin/offers', auth, (req,res)=>{
  const title=cleanString(req.body.title,100),description=cleanString(req.body.description,500);
  if(!title) return res.status(400).json({error:'অফারের শিরোনাম লিখুন'});
  const info=db.prepare('INSERT INTO offers(title,description,active) VALUES (?,?,?)').run(title,description,req.body.active===false?0:1);
  res.status(201).json({id:info.lastInsertRowid});
});
app.put('/api/admin/offers/:id', auth, (req,res)=>{
  const title=cleanString(req.body.title,100),description=cleanString(req.body.description,500);
  if(!title) return res.status(400).json({error:'অফারের শিরোনাম লিখুন'});
  db.prepare('UPDATE offers SET title=?,description=?,active=? WHERE id=?').run(title,description,req.body.active===false?0:1,Number(req.params.id));res.json({ok:true});
});
app.delete('/api/admin/offers/:id', auth, (req,res)=>{db.prepare('DELETE FROM offers WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.get('/api/admin/orders', auth, (req,res)=>res.json(db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 300').all()));
app.patch('/api/admin/orders/:id', auth, (req,res)=>{
  const status=cleanString(req.body.status,30);
  if(!['Pending','Processing','Completed','Cancelled'].includes(status)) return res.status(400).json({error:'অবস্থা সঠিক নয়'});
  const info=db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,Number(req.params.id));
  if(!info.changes) return res.status(404).json({error:'অর্ডার পাওয়া যায়নি'});res.json({ok:true});
});
app.get('/api/admin/settings', auth, (req,res)=>res.json(Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]))));
app.put('/api/admin/settings', auth, (req,res)=>{
  const allowed=['siteName','whatsapp','telegram','notice'];
  const up=db.prepare('INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  for(const k of allowed) if(typeof req.body[k]==='string') up.run(k,req.body[k].trim().slice(0,250));
  res.json({ok:true});
});
// Public catalogue: only active products/offers; never exposes admin/customer data.
app.get('/api/catalog', (req,res)=>res.json({
  packages:db.prepare('SELECT id,name,category,country,price FROM packages WHERE active=1 ORDER BY country,category,price').all(),
  offers:db.prepare('SELECT title,description FROM offers WHERE active=1 ORDER BY id DESC').all(),
  settings:Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]))
}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'সার্ভারে সমস্যা হয়েছে'});});
app.listen(PORT,()=>console.log(`RTB TOP UP server listening on ${PORT}`));

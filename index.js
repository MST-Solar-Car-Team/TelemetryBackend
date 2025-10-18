import express from 'express'
import session from 'express-session'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import { DuckDBInstance } from '@duckdb/node-api';
import fs from 'fs'

const instance = await DuckDBInstance.create(':memory:');
const connection = await instance.connect();

// users database
const users = [
  {
    id: '1',
    username: 'user1',
    password: '$2a$12$aVafeJDa1ZCiEbNqz7wpBe1sGIh1NiqlM99pmUFhtWEDFLbPIPOX2', // hashed password for 'password1'
    role: 'admin'
  },
  {
    id: '2',
    username: 'user2',
    password: '$2a$12$dfwz.fwKTvg19YvQMnnmu.F02P1eakBFuohICrFEK6pcGItQlzx9S', // hashed password for 'password2'
    role: 'user'
  },
];

function parquetPathFromId(id) {
    return `./data/telemetry/${id}.parquet`
}

async function findUserByUsername(username) {
    return users.find(u => u.username === username) || null
}
async function validatePassword(user, password) {
    return await bcrypt.compare(password, user.password)
}

passport.use(new LocalStrategy.Strategy(
  { usernameField: 'username', passwordField: 'password' },
  async (username, password, done) => {
      try {
          const user = await findUserByUsername(username)
          if (!user) return done(null, false, { message: 'Invalid credentials' })
            const ok = await validatePassword(user, password)
        if (!ok) return done(null, false, { message: 'Invalid credentials' })
            // include username so req.user exposes it
            return done(null, { id: user.id, username: user.username, role: user.role || 'user' })
    } catch (e) { return done(e) }
}
))

passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser(async (id, done) => {
    const user = users.find(u => u.id === id)
    if (!user) return done(null, false)
        // include username when restoring session
        done(null, { id: user.id, username: user.username, role: user.role || 'user' })
})

const app = express();

app.use(cors({
  origin: ['http://localhost:5173'],
  credentials: true
}))

app.use(express.json())

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // change to true when we https
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8 // 8 hours
  }
}))

app.use(passport.initialize())
app.use(passport.session())

function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next()
  res.status(401).json({ error: 'Unauthorized' })
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' })
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' })
    next()
  }
}

app.post('/api/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err)
    if (!user) return res.status(400).json({ error: info?.message || 'Login failed' })
    req.logIn(user, (err2) => {
      if (err2) return next(err2)
      // return username as part of the login response
      res.json({ id: user.id, username: user.username, email: user.email, role: user.role })
    })
  })(req, res, next)
})

app.post('/api/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie('sid')
      res.json({ ok: true })
    })
  })
})

app.get('/api/me', (req, res) => {
  if (!req.isAuthenticated()) return res.json(null)
  // req.user now includes username
  res.json(req.user)
})

// --- list available parquet files
app.get('/api/files', ensureAuth, async (req, res, next) => {
  try {
    const files = await fs.promises.readdir('./data/telemetry')
    const parquetFiles = files
      .filter(f => f.endsWith('.parquet'))
      .map(f => f.replace(/\.parquet$/i, ''))
    res.json(parquetFiles)
  } catch (e) { next(e) }
})

// --- parquet file metadata, not used yet/at all
app.get('/api/files/:id/meta', ensureAuth, async (req, res, next) => {
  try {
    const id = req.params.id
    const path = parquetPathFromId(id)
    const rows = await connection.run(`
      SELECT column_name, data_type
      FROM parquet_schema('${path}')
    `)
    let rowsw = await rows.getRows()
    const count = await connection.run(`SELECT COUNT(*) AS n FROM read_parquet('${path}')`).getRows()
    res.json({ columns: rowsw, rows: count[0].n })
  } catch (e) { next(e) }
})

// --- arrow streaming (default) or JSON for fallback
app.get('/api/files/:id/data', ensureAuth, async (req, res, next) => {
  try {
    const id = req.params.id
    const path = parquetPathFromId(id)
    if (fs.existsSync(path) === false) {
      return res.status(404).json({ error: 'File not found' })
    }

    // query parameters
    const select = (req.query.select ?? '*').toString()
    const where  = (req.query.where  ?? 'TRUE').toString()
    const limit  = Math.min(parseInt(req.query.limit ?? '50000', 10), 200000) // safety cap
    const fmt    = (req.query.format ?? 'arrow').toString()    // 'arrow' | 'json'
    const order  = (req.query.order  ?? '').toString()

    const orderClause = order ? `ORDER BY ${order}` : ''
    const sql = `
      SELECT ${select}
      FROM '${path}'
      WHERE ${where}
      ${orderClause}
      LIMIT ${limit}
    `

    if (fmt === 'json') {
      const rows = await connection.run(sql)
      let rowsw = await rows.getRows()
      console.log('Returning JSON data', rowsw)
      res.json(rowsw)
      return
    }

    // arrow stream response
    // console.log('Streaming Arrow data with SQL:', sql)
    // duckdb node api: each chunk is an Arrow RecordBatch in IPC format
    const reader = await connection.streamAndReadAll(sql)

    const rows = reader.getRowObjectsJson();  // or getColumnsObjectJson()
    const buf  = Buffer.from(JSON.stringify(rows));
    res.end(buf);
  } catch (e) { next(e) }
})

// admin-only endpoint, change later
app.get('/api/admin/telemetry', requireRole('admin'), (req, res) => {
  res.json({ secret: 'telemetry controls' })
})

app.listen(3000, () => console.log('API on http://localhost:3000'))
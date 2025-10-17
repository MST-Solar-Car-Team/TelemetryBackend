import express from 'express'
import session from 'express-session'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import duckdb from 'duckdb'

const DB = new duckdb.Database(':memory:')
const CONNECTION = DB.connect()

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

// --- parquet file metadata, not used yet/at all
app.get('/api/files/:id/meta', ensureAuth, async (req, res, next) => {
  try {
    const id = req.params.id
    const path = parquetPathFromId(id)
    const rows = await CONNECTION.all(`
      SELECT column_name, data_type
      FROM parquet_schema('${path}')
    `)
    const count = await CONNECTION.all(`SELECT COUNT(*) AS n FROM '${path}'`)
    res.json({ columns: rows, rows: count[0].n })
  } catch (e) { next(e) }
})

// --- arrow streaming (default) or JSON for fallback
app.get('/api/files/:id/data', ensureAuth, async (req, res, next) => {
  try {
    const id = req.params.id
    const path = parquetPathFromId(id)

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
      const rows = await CONNECTION.all(sql)
      res.json(rows)
      return
    }

    // arrow stream response
    res.setHeader('Content-Type', 'application/vnd.apache.arrow.stream')
    // duckdb node api: each chunk is an Arrow RecordBatch in IPC format
    await CONNECTION.stream(sql, (chunk) => {
      res.write(Buffer.from(chunk)) // chunk is a Uint8Array
    })
    res.end()
  } catch (e) { next(e) }
})

// admin-only endpoint, change later
app.get('/api/admin/telemetry', requireRole('admin'), (req, res) => {
  res.json({ secret: 'telemetry controls' })
})

app.listen(3000, () => console.log('API on http://localhost:3000'))
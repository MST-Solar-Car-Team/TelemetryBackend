import express from 'express'
import session from 'express-session'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import { DuckDBInstance } from '@duckdb/node-api';
import fs from 'fs'
import path from 'path'

const instance = await DuckDBInstance.create(':memory:');
const connection = await instance.connect();

const telemetryDir = path.resolve('./data/telemetry')

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

const SAFE_ID_RE = /^[A-Za-z0-9_-]+$/
const MAX_LIMIT = 200000

function resolveParquetPath(id) {
  if (!SAFE_ID_RE.test(id)) return null
  const filePath = path.resolve(telemetryDir, `${id}.parquet`)
  if (!filePath.startsWith(`${telemetryDir}${path.sep}`)) return null
  return filePath
}

function quoteIdent(name) {
  return `"${name.replace(/"/g, '""')}"`
}

function escapeSqlString(value) {
  return value.replace(/'/g, "''")
}

async function getParquetSchema(filePath) {
  const escapedPath = escapeSqlString(filePath)
  const rows = await connection.run(`DESCRIBE SELECT * FROM read_parquet('${escapedPath}')`)
  const rowsw = await rows.getRows()
  return rowsw.map(row => {
    if (Array.isArray(row)) {
      return { column_name: row[0], data_type: row[1] }
    }
    return {
      column_name: row.column_name ?? row.name,
      data_type: row.data_type ?? row.type
    }
  })
}

async function getParquetColumns(filePath) {
  const schema = await getParquetSchema(filePath)
  return schema.map(row => row.column_name).filter(Boolean)
}

function parseSelect(selectRaw, allowedColumns) {
  const trimmed = (selectRaw ?? '').toString().trim()
  if (!trimmed || trimmed === '*') return '*'
  const cols = trimmed.split(',').map(col => col.trim()).filter(Boolean)
  if (!cols.length) return '*'
  const invalid = cols.filter(col => !allowedColumns.has(col))
  if (invalid.length) {
    throw new Error(`Invalid select columns: ${invalid.join(', ')}`)
  }
  return cols.map(col => quoteIdent(col)).join(', ')
}

function parseOrder(orderRaw, allowedColumns) {
  const trimmed = (orderRaw ?? '').toString().trim()
  if (!trimmed) return ''
  const clauses = trimmed.split(',').map(clause => clause.trim()).filter(Boolean)
  if (!clauses.length) return ''
  const parsedClauses = clauses.map(clause => {
    const parts = clause.split(/\s+/).filter(Boolean)
    if (parts.length === 0 || parts.length > 2) {
      throw new Error('Invalid order clause')
    }
    const column = parts[0]
    if (!allowedColumns.has(column)) {
      throw new Error(`Invalid order column: ${column}`)
    }
    let direction = ''
    if (parts[1]) {
      const upper = parts[1].toUpperCase()
      if (upper !== 'ASC' && upper !== 'DESC') {
        throw new Error(`Invalid order direction: ${parts[1]}`)
      }
      direction = ` ${upper}`
    }
    return `${quoteIdent(column)}${direction}`
  })
  return `ORDER BY ${parsedClauses.join(', ')}`
}

function parseWhereValue(raw) {
  const trimmed = raw.trim()
  if (/^[-+]?\d+(\.\d+)?$/.test(trimmed)) return trimmed
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    const inner = trimmed.slice(1, -1)
    return `'${inner.replace(/'/g, "''")}'`
  }
  throw new Error('Invalid where value')
}

function parseWhere(whereRaw, allowedColumns) {
  const trimmed = (whereRaw ?? '').toString().trim()
  if (!trimmed || trimmed.toUpperCase() === 'TRUE') return 'TRUE'
  const clauses = trimmed.split(/\s+AND\s+/i).map(clause => clause.trim()).filter(Boolean)
  const parsedClauses = clauses.map(clause => {
    const match = clause.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*(=|!=|<=|>=|<|>)\s*(.+)$/)
    if (!match) throw new Error('Invalid where clause')
    const [, column, operator, valueRaw] = match
    if (!allowedColumns.has(column)) {
      throw new Error(`Invalid where column: ${column}`)
    }
    const value = parseWhereValue(valueRaw)
    return `${quoteIdent(column)} ${operator} ${value}`
  })
  return parsedClauses.join(' AND ')
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
      res.json({ id: user.id, username: user.username, role: user.role })
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
    const files = await fs.promises.readdir(telemetryDir)
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
    const path = resolveParquetPath(id)
    if (!path) {
      return res.status(400).json({ error: 'Invalid file id' })
    }
    if (fs.existsSync(path) === false) {
      return res.status(404).json({ error: 'File not found' })
    }
    const escapedPath = escapeSqlString(path)
    const schema = await getParquetSchema(path)
    const count = await connection.run(`SELECT COUNT(*) AS n FROM read_parquet('${escapedPath}')`).getRows()
    res.json({ columns: schema, rows: count[0].n })
  } catch (e) { next(e) }
})

// --- arrow streaming (default) or JSON for fallback
app.get('/api/files/:id/data', ensureAuth, async (req, res, next) => {
  try {
    const id = req.params.id
    const path = resolveParquetPath(id)
    if (!path) {
      return res.status(400).json({ error: 'Invalid file id' })
    }
    if (fs.existsSync(path) === false) {
      return res.status(404).json({ error: 'File not found' })
    }

    // query parameters
    const select = (req.query.select ?? '*').toString()
    const where  = (req.query.where  ?? 'TRUE').toString()
    const limitRaw = parseInt(req.query.limit ?? '50000', 10)
    const limit  = Number.isFinite(limitRaw) && limitRaw >= 0
      ? Math.min(limitRaw, MAX_LIMIT)
      : 50000
    const fmt    = (req.query.format ?? 'arrow').toString()    // 'arrow' | 'json'
    const order  = (req.query.order  ?? '').toString()

    const allowedColumns = new Set(await getParquetColumns(path))
    let selectClause
    let whereClause
    let orderClause
    try {
      selectClause = parseSelect(select, allowedColumns)
      whereClause = parseWhere(where, allowedColumns)
      orderClause = parseOrder(order, allowedColumns)
    } catch (error) {
      return res.status(400).json({ error: error.message || 'Invalid query parameters' })
    }
    const escapedPath = escapeSqlString(path)
    const sql = `
      SELECT ${selectClause}
      FROM '${escapedPath}'
      WHERE ${whereClause}
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

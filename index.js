import express from 'express'
import session from 'express-session'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import bcrypt from 'bcryptjs'
import cors from 'cors'

// users database
const users = [
  {
    id: '1',
    username: 'user1',
    password: '$2a$12$aVafeJDa1ZCiEbNqz7wpBe1sGIh1NiqlM99pmUFhtWEDFLbPIPOX2', // hashed password for 'password1'
  },
  {
    id: '2',
    username: 'user2',
    password: '$2a$12$dfwz.fwKTvg19YvQMnnmu.F02P1eakBFuohICrFEK6pcGItQlzx9S', // hashed password for 'password2'
  },
];


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
            return done(null, { id: user.id, email: user.email, role: user.role || 'user' })
    } catch (e) { return done(e) }
}
))

passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser(async (id, done) => {
    const user = users.find(u => u.id === id)
    if (!user) return done(null, false)
        done(null, { id: user.id, email: user.email, role: user.role || 'user' })
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
    maxAge: 1000 * 60 * 60 * 8
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
      res.json({ id: user.id, email: user.email, role: user.role })
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
  res.json(req.user)
})

app.listen(3000, () => console.log('API on http://localhost:3000'))
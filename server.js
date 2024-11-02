const express = require('express');
const morgan = require('morgan');
const winston = require('winston');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const app = express();
const port = process.env.PORT || 3000;

// Logger setup
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'honeypot.log' })
  ]
});

// Rate limiter setup
const rateLimiter = new RateLimiterMemory({
  points: 5,
  duration: 60
});

// Middleware
app.use(express.json());
app.use(morgan('combined'));

// Honeypot middleware
const honeypotMiddleware = (req, res, next) => {
  const suspicious = [
    req.headers['user-agent']?.toLowerCase().includes('bot'),
    req.headers['x-forwarded-for'],
    req.body?.admin,
    req.query?.admin
  ].some(Boolean);

  if (suspicious) {
    logger.warn({
      type: 'suspicious_access',
      ip: req.ip,
      path: req.path,
      headers: req.headers,
      body: req.body,
      query: req.query
    });
  }
  next();
};

app.use(honeypotMiddleware);

// Fake admin login endpoint
app.post('/admin-login', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
    logger.info({
      type: 'honeypot_trigger',
      endpoint: 'admin-login',
      ip: req.ip,
      body: req.body
    });
    res.status(401).json({ error: 'Invalid credentials' });
  } catch {
    res.status(429).json({ error: 'Too many attempts' });
  }
});

// Fake API endpoint
app.get('/api/users', (req, res) => {
  logger.info({
    type: 'honeypot_trigger',
    endpoint: 'api-users',
    ip: req.ip,
    query: req.query
  });
  res.status(403).json({ error: 'Unauthorized access' });
});

// Hidden form endpoint
app.post('/contact-form', (req, res) => {
  logger.info({
    type: 'honeypot_trigger',
    endpoint: 'contact-form',
    ip: req.ip,
    body: req.body
  });
  res.status(200).json({ message: 'Form submitted successfully' });
});

app.listen(port, () => {
  console.log(`Honeypot server running on port ${port}`);
});
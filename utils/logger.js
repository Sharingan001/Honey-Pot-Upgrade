const winston = require('winston');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'honeypot.log' }),
    new winston.transports.Console()
  ]
});

const enrichLog = (data) => {
  const geo = geoip.lookup(data.ip);
  const ua = new UAParser(data.headers?.['user-agent']).getResult();
  
  return {
    ...data,
    timestamp: new Date().toISOString(),
    geolocation: geo,
    device: {
      browser: ua.browser,
      os: ua.os,
      device: ua.device
    },
    risk_score: calculateRiskScore(data, geo, ua)
  };
};

const calculateRiskScore = (data, geo, ua) => {
  let score = 0;
  
  // Location-based scoring
  if (geo && ['CN', 'RU', 'NK'].includes(geo.country)) score += 30;
  
  // Bot detection
  if (ua.browser.name?.toLowerCase().includes('bot')) score += 25;
  
  // Suspicious patterns
  if (data.headers?.['x-forwarded-for']) score += 15;
  if (data.path?.includes('admin') || data.path?.includes('wp-')) score += 20;
  
  return Math.min(score, 100);
};

module.exports = { logger, enrichLog };
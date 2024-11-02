const crypto = require('crypto');
const UAParser = require('ua-parser-js');

class DeviceFingerprint {
  static generate(req) {
    const components = [
      req.headers['user-agent'],
      req.headers['accept-language'],
      req.headers['accept-encoding'],
      req.ip,
      req.headers['sec-ch-ua'],
      req.headers['sec-ch-ua-platform']
    ];

    return crypto
      .createHash('sha256')
      .update(components.filter(Boolean).join('|'))
      .digest('hex');
  }

  static analyzeHeaders(headers) {
    const ua = new UAParser(headers['user-agent']);
    const result = ua.getResult();
    
    const inconsistencies = [];
    
    // Check for header inconsistencies
    if (headers['accept-language'] && !headers['accept-encoding']) {
      inconsistencies.push('missing_encoding');
    }
    
    // Check for suspicious browser/OS combinations
    if (result.os.name === 'Windows' && result.browser.name === 'Safari') {
      inconsistencies.push('invalid_browser_os');
    }
    
    return {
      fingerprint: this.generate({ headers, ip: headers['x-forwarded-for'] }),
      inconsistencies,
      browserProfile: result
    };
  }
}

module.exports = DeviceFingerprint;
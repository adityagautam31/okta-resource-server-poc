const express = require('express');
const OktaJwtVerifier = require('@okta/jwt-verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// ========== CONFIGURE THESE 3 VALUES ==========
const OKTA_DOMAIN = 'https://demo-amethyst-tyrannosaurus-16806.okta.com';          // e.g. https://dev-123456.okta.com
const AUTH_SERVER_ID = 'default';                        // usually "default"
const AUDIENCE = 'https://YOUR_RENDER_URL.onrender.com'; // will update after deploy
// ================================================

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: `${OKTA_DOMAIN}/oauth2/${AUTH_SERVER_ID}`,
});

app.get('/', (req, res) => {
  res.send('Okta Resource Server POC is running');
});

app.get('/api/items', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/Bearer (.+)/);

  if (!match) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const accessToken = match[1];

  try {
    const jwt = await oktaJwtVerifier.verifyAccessToken(accessToken, AUDIENCE);

    const scopes = jwt.claims.scp || [];
    if (!scopes.includes('read:items')) {
      return res.status(403).json({ 
        error: 'Missing required scope: read:items',
        yourScopes: scopes 
      });
    }

    res.json({
      message: 'Success! Token is valid for this Resource Server',
      subject: jwt.claims.sub,
      scopes: scopes,
      audience: jwt.claims.aud
    });
  } catch (err) {
    res.status(401).json({ 
      error: 'Invalid token', 
      details: err.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

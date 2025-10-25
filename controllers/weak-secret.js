const app = require('express')();
const jwt = require('jsonwebtoken');
const { extractBearerToken, HS_SECRET } = require('../lib/jwt-utils');
const MIN_SECRET_LENGTH = 32;

/**
 * @swagger
 * /weak-secret:
 *   post:
 *     summary: Exploit Weak Secret vulnerability
 *     tags: [Weak Secret]
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Authorization token (JWT)
 *     responses:
 *       200:
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         content:
 *           application/json:
 *             schema:
 *               type: string
*/
app.post('/', async(req,res) => {
    const token = extractBearerToken(req);

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        // Enforce a minimum secret length and use configured secret (do not hard-code)
        if(!HS_SECRET || HS_SECRET.length < MIN_SECRET_LENGTH) {
            console.warn('HS secret is missing or too short; refusing to verify');
            return res.sendStatus(500);
        }

        const payload = jwt.verify(token, HS_SECRET, { algorithms: ['HS256'] });

        if(payload['admin']) {
            payload['flag'] = 'hakai{W34k_s3cr3t_4tt4ck}';
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /weak-secret:
 *   get:
 *     summary: Return JWT token
 *     tags: [Weak Secret]
 *     responses:
 *       200:
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT
*/
app.get('/', async(req,res) => {
    const payload = {
        username: 'guest',
        admin: false
    };

    // Use configured HS secret to sign tokens
    if(!HS_SECRET || HS_SECRET.length < MIN_SECRET_LENGTH) {
        console.warn('HS secret is missing or too short; cannot sign tokens');
        return res.status(500).json({ error: 'server misconfiguration' });
    }

    const token = jwt.sign(payload, HS_SECRET, { algorithm: 'HS256' });

    return res.json({ token });
});

module.exports = app;
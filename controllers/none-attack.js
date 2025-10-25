const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const { extractBearerToken } = require('../lib/jwt-utils');

/**
 * @swagger
 * /none-attack:
 *   post:
 *     summary: Exploit None Attack vulnerability
 *     tags: [None Attack]
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
app.post("/", async (req,res) => {
    const token = extractBearerToken(req);

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header || !header.alg) return res.sendStatus(401);

        // Explicitly disallow 'none' algorithm
        if(header.alg.toLowerCase() === 'none') {
            console.warn('Token uses none algorithm - rejected');
            return res.sendStatus(401);
        }

        let payload;

        // Only accept HS256 or RS256 and verify with the corresponding trusted key
        if(header.alg === 'HS256') {
            // Prefer configured secret; fallback to local file only if configured
            const hs = process.env.JWT_HS_SECRET || 'HS_S3cr3t_k3y';
            payload = jwt.verify(token, hs, { algorithms: ['HS256'] });
        } else if(header.alg === 'RS256') {
            const pub = fs.readFileSync(__dirname + '/../keys/public.pem', 'utf-8');
            payload = jwt.verify(token, pub, { algorithms: ['RS256'] });
        } else {
            // unsupported algorithm
            return res.sendStatus(401);
        }

        if(payload['admin']) {
            payload['flag'] = 'hakai{N0n3_4tt4ck_1s_c00l}'
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /none-attack:
 *   get:
 *     summary: Return JWT token
 *     tags: [None Attack]
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
app.get('/', async (req,res) => {
    const algorithms = ['HS256', 'RS256'];
    
    const keys = {
        'HS256': 'HS_S3cr3t_k3y',
        'RS256': fs.readFileSync(__dirname + '/../keys/private.pem', 'utf-8')
    };
    
    const payload = {
        username: 'guest',
        admin: false
    };

    const alg = algorithms[Math.floor(Math.random() * algorithms.length)]

    return res.json({ token: jwt.sign(payload, keys[alg], { algorithm: alg }) });
});

module.exports = app;

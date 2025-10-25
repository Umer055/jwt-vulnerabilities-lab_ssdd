const express = require('express');
const jwt = require('jsonwebtoken');
const sequelize = require('../database/db');
const fs = require('fs');
const path = require('path');
const { extractBearerToken } = require('../lib/jwt-utils');
const { QueryTypes } = require('sequelize');

const app = express();

/**
 * @swagger
 * /kid-injection/path-traversal:
 *   post:
 *     summary: Exploit KID Path traversal vulnerability
 *     tags: [KID Header Injection]
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
app.post('/path-traversal', async (req,res) => {
    const token = extractBearerToken(req);

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header || !header.kid) return res.sendStatus(401);

        // Validate kid format: only allow 32 hex characters (no path traversal)
        const kid = header.kid;
        if(!/^[0-9a-fA-F]{32}$/.test(kid)) {
            console.warn('Invalid kid format');
            return res.sendStatus(401);
        }

        // Resolve to keys directory and ensure basename equals kid
        const keyPath = path.join(__dirname, '..', 'keys', kid);
        if(path.basename(keyPath) !== kid) return res.sendStatus(401);

        const secretKey = fs.readFileSync(keyPath, 'utf-8');

        // Using file content like a secret key (still HS256)
        const payload = jwt.verify(token, secretKey, { algorithms: ['HS256'] });

        if(payload['admin']) {
            payload['flag'] = 'hakai{k1d_h34d3r_p4th_tr4v3r54l}'
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
})

/**
 * @swagger
 * /kid-injection/sql-injection:
 *   post:
 *     summary: Exploit KID SQL Injection vulnerability
 *     tags: [KID Header Injection]
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
app.post('/sql-injection', async(req,res) => {
    const token = extractBearerToken(req);

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header || !header.kid) {
            return res.sendStatus(401);
        }

        const kid = header.kid;
        if(!/^[0-9a-fA-F-]{36}$/.test(kid) && !/^[0-9a-fA-F]{32}$/.test(kid)) {
            // Accept either UUID or 32-hex id; otherwise reject
            return res.sendStatus(401);
        }

        // Parameterized query to avoid SQL injection
        const [result] = await sequelize.query('SELECT * FROM JwtKeys WHERE uuid = ?', {
            replacements: [kid],
            type: QueryTypes.SELECT
        });

        if(!result) {
            return res.sendStatus(401);
        }

        const key = result.key || result['key'];

        // Using secret key retrieved from database. Restrict algorithm to HS256.
        const payload = jwt.verify(token, key, { algorithms: ['HS256'] });

        if(payload['admin']) {
            payload['flag'] = 'hakai{sql_1nj3ct10n_k1d_h34d3r}'
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
})

/**
 * @swagger
 * /kid-injection:
 *   get:
 *     summary: Return JWT token
 *     tags: [KID Header Injection]
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
    const header = {
        kid: '698dc19d489c4e4db73e28a713eab07b'
    };
    
    const payload = {
        username: 'guest',
        admin: false,
    };

    const kid = header.kid;
    // Validate file-based kid and read key
    if(!/^[0-9a-fA-F]{32}$/.test(kid)) return res.sendStatus(500);

    const secretKey = fs.readFileSync(path.join(__dirname, '..', 'keys', kid), 'utf-8');

    const token = jwt.sign(payload, secretKey, { algorithm: 'HS256', header });

    return res.json({ token });
})


module.exports = app;
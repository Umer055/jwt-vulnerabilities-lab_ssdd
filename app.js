const express = require('express');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8000;

// Basic security middleware
app.use(helmet());
app.use(express.json());

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'JWT Labs',
            version: '1.0.0',
            description: '',
        },
        servers: [
            {
                url: 'http://localhost:8000',
            },
        ],
    },
    apis: ['./controllers/*.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.get('/', (req,res) => {
    return res.redirect('/swagger');
})

app.use("/", express.static(__dirname + '/public'));

app.use('/weak-secret', require('./controllers/weak-secret'));
app.use('/none-attack', require('./controllers/none-attack'));
app.use('/kid-injection', require('./controllers/kid-injection'));
app.use('/jku-injection', require('./controllers/jku-injection'));
app.use('/algorithm-confusion', require('./controllers/algorithm-confusion'));

app.listen(PORT, () => {
    console.log(`Listening on http://localhost:${PORT}/`);
});

const { Sequelize } = require('sequelize');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './db.sqlite',
    logging: false
});

console.log("====Database====")

sequelize.authenticate().then(() => {
    console.log('Connected with success');
}).catch(err => {
    console.error(`Error with connect: ${err}`);
});

module.exports = sequelize;
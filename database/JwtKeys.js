const { DataTypes } = require('sequelize');
const sequelize = require('./db');

const JwtKeys = sequelize.define('JwtKeys', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        unique: true
    },
    uuid: {
        type: DataTypes.UUID,
        unique: true,
        allowNull: false
    },
    key: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    }
}, {
    createdAt: false,
    updatedAt: false
});

JwtKeys.sync();

module.exports = JwtKeys;
'use strict';

const { createHmac } = require('node:crypto');

const createHmac256 = (data, key) => createHmac('sha256', key).update(data).digest();

module.exports = { createHmac256 };

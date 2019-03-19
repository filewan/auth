const mongoose = require('mongoose');

const { Schema } = mongoose;
mongoose.Promise = global.Promise;

module.exports = mongoose.model('User', new Schema({
  username: { type: String, index: true },
  password: String,
  role: String,
}, { collection: 'User' }));

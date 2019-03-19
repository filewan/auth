const mongoose = require('mongoose');
const config = require('./config');

module.exports = (callback) => {
  const db = mongoose.connection;

  db.on('connecting', () => {
    console.log('connecting...');
  });
  db.on('error', (error) => {
    console.error(error);
  });
  db.on('connected', () => {
    console.log('MongoDB connected!');
  });
  db.once('open', () => {
    console.log('MongoDB connection opened!');
  });
  db.on('reconnected', () => {
    console.log('MongoDB reconnected!');
  });
  db.on('disconnected', () => {
    console.log('MongoDB disconnected!');
  });
  mongoose.connect(config.get('db:host'), {
    server: {
      auto_reconnect: true,
      reconnectInterval: config.get('db:reconnectInterval'),
    },
  }).catch((err) => {
    console.log(err);
  });

  callback(db);
};

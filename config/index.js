const nconf = require('nconf');

function Config() {
  nconf.argv()
    .env();
  const env = nconf.get('NODE_ENV') || 'development';
  nconf.file(env, `./config/${env.toLowerCase()}.json`);
}

Config.prototype.get = key => nconf.get(key);

module.exports = new Config();

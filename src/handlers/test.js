const User = require('./../user');
const {CLIENT_ID_PATTERN} = require('../utils');
const Debug = require('debug');

const debug = Debug('handlers.test');

class Handler {
  constructor({name, cfg}) {
  }

  get identityProviderId() {
    return 'test';
  }

  identityFromClientId(clientId) {
    const patternMatch = CLIENT_ID_PATTERN.exec(clientId);
    return patternMatch && patternMatch[1];
  }

  userFromClientId(clientId) {
    const identity = this.identityFromClientId(clientId);
    const identityId = identity.replace('test/', '');
    return this.userFromIdentityId(identityId);
  }

  async userFromRequest(req, res) {
    const accessToken = req.headers['authorization'];
    if (!accessToken || !accessToken.startsWith('Bearer ')) {
      debug('invalid auth header');
      return;
    }
    const identityId = accessToken.split(' ')[1];
    return this.userFromIdentityId(identityId);
  }

  userFromIdentityId(identityId) {
    if (identityId === 'invalid') {
      debug('invalid token');
      return;
    }

    const user = new User();
    user.identity = 'test/' + identityId;
    user.addRole('test:' + identityId);
    return user;
  }
}

module.exports = Handler;

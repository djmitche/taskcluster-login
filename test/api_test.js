const assume = require('assume');
const debug = require('debug')('test:api');
const helper = require('./helper');
const request = require('superagent');

suite('api_test.js', function() {
  helper.withServer();

  suite('oidcCredentials', function() {
    test('returns 400 for a call without a header', async function() {
      try {
        await helper.login.oidcCredentials('test');
      } catch (e) {
        assume(e.statusCode).to.equal(400);
        assume(e.code).to.equal('InputError');
        return;
      }
      throw new Error('should have failed');
    });

    test('returns credentials for "test" provider', async function() {
      let res = await request
        .get(helper.baseUrl + '/oidc-credentials/test')
        .set('Authorization', 'Bearer let-me-in');
      let resp = JSON.parse(res.text);
      assume(resp.credentials.clientId).to.equal('test/let-me-in');
      let until_exp = new Date(resp.expires) - new Date();
      assume(until_exp).greaterThan(14 * 60 * 1000);
    });

  });

  suite('ping', function() {
    test('pings', async () => {
      await helper.login.ping();
    });
  });
});

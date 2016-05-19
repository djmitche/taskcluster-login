require('mocha')

suite('API', function() {
  var _           = require('lodash');
  var assume      = require('assume');
  var debug       = require('debug')('test:api');
  var helper      = require('./helper');

  helper.setup();

  suite("ping", function() {
    test("pings", async () => {
      await helper.login.ping();
    });
  });

  suite("persona", function() {
    test("generates credentials", async () => {
      let creds = await helper.login.credentialsFromPersonaAssertion({
        assertion: "abcd",
        audience: 'https://tools.taskcluster.net:443',
      });
      let cert = JSON.parse(creds.certificate);
      // check that the fake authorizer authorized the user that the fake verifier verified
      assume(helper.authorizer.identitiesSeen).to.contain('persona/nobody@persona.org');
      assume(cert.scopes).to.contain("assume:fake-authorizer:nobody@persona.org");
    });

    test("fails with 400 for a PersonaError", async () => {
      helper.personaVerifier.error = new Error("oh noes");
      helper.personaVerifier.error.code = "PersonaError";
      try {
        await helper.login.credentialsFromPersonaAssertion({
          assertion: "abcd",
          audience: 'https://tools.taskcluster.net:443',
        });
      } catch(err) {
        assume(err.statusCode).to.equal(400);
        return;
      }
      throw new Error("unexpected success");
    });
  });

  suite("restrictedCredentials", function() {
    test("succeeds with appropriate scopes", async () => {
      let creds = await helper.login.restrictedCredentials({
        scopes: ['subscope1', 'subscope2'],
        clientIdSuffix: 'testy',
      });
      let cert = JSON.parse(creds.certificate);
      assume(cert.scopes).to.contain("subscope1");
      assume(creds.clientId).to.equal('test-client/testy');
    });

    test("fails without scopes satisfying requested scopes", async () => {
      helper.scopes('somescope');
      try {
        await helper.login.restrictedCredentials({
          scopes: ['another-scope'],
          clientIdSuffix: 'testy',
        });
      } catch(err) {
        assume(err.code).to.equal('InsufficientScopes');
        return
      }
      throw new Error("unexpected success");
    });

    // TODO: w/o auth:create-client:foo
  });
});


const assume = require('assume');
const Handler = require('../src/handlers/mozilla-auth0');
const {encode} = require('../src/utils');
const {secrets} = require('./helper');

suite('handlers_mozilla_auth0_test.js', function() {

  suite('conversions', function() {
    let handler;

    setup(function() {
      handler = new Handler({
        name: 'mozilla-auth0',
        cfg: {
          handlers: {
            'mozilla-auth0': {
              domain:'login-test.taskcluster.net',
              apiAudience: 'login-test.taskcluster.net',
              clientId: 'abcd',
              clientSecret: 'defg',
            },
          },
        },
      });
    });

    const testClientId = (name, {clientId, userId, identity}) => {
      test(name, function() {
        assume(handler.userIdFromClientId(clientId)).to.equal(userId);
        assume(handler.identityFromClientId(clientId)).to.equal(identity);
      });
    };

    const testProfile = (name, {profile, identity}) => {
      test(name, function() {
        assume(handler.identityFromProfile(profile)).to.equal(identity);
        const clientId = `${identity}/abc`;
        assume(handler.identityFromClientId(clientId)).to.equal(identity);
      });
    };

    testClientId('simple LDAP clientId', {
      clientId: 'mozilla-auth0/ad|Mozilla-LDAP|dmitchell/abc',
      userId: 'ad|Mozilla-LDAP|dmitchell',
      identity: 'mozilla-auth0/ad|Mozilla-LDAP|dmitchell',
    });

    testClientId('simple LDAP clientId with just a trailing /', {
      clientId: 'mozilla-auth0/ad|Mozilla-LDAP|dmitchell/',
      userId: 'ad|Mozilla-LDAP|dmitchell',
      identity: 'mozilla-auth0/ad|Mozilla-LDAP|dmitchell',
    });

    testClientId('github clientId', {
      clientId: 'mozilla-auth0/github|1234|helfi92/',
      userId: 'github|1234',
      identity: 'mozilla-auth0/github|1234|helfi92',
    });

    testClientId('encoded clientId', {
      clientId: 'mozilla-auth0/email|slashy!2Fslashy/abc',
      userId: 'email|slashy/slashy',
      identity: 'mozilla-auth0/email|slashy!2Fslashy',
    });

    testProfile('simple LDAP profile', {
      profile: {
        user_id: 'ad|Mozilla-LDAP|dmitchell',
        identities: [{provider: 'ad', connection: 'Mozilla-LDAP'}],
      },
      identity: 'mozilla-auth0/ad|Mozilla-LDAP|dmitchell',
    });

    testProfile('email profile with slashes', {
      profile: {
        user_id: 'email|slashy/slashy',
        identities: [{provider: 'email', connection: 'email'}],
      },
      identity: 'mozilla-auth0/email|slashy!2Fslashy',
    });

    testProfile('google profile', {
      profile: {
        user_id: 'google-oauth2|392759287359',
        identities: [{provider: 'google-oauth2', connection: 'google-oauth2'}],
      },
      identity: 'mozilla-auth0/google-oauth2|392759287359',
    });

    testProfile('github profile', {
      profile: {
        nickname: 'helfi92',
        user_id: 'github|1234',
        identities: [{provider: 'github', connection: 'github'}],
      },
      identity: 'mozilla-auth0/github|1234|helfi92',
    });

    test('userIdFromClientId with non-matching clientId', function() {
      assume(handler.userIdFromClientId('no-slashes')).to.equal(undefined);
    });

    const assertRoles = (user, roles) => {
      user.roles.sort();
      roles.sort();
      assume(user.roles).to.deeply.equal(roles);
    };

    test('user for ldap profile', function() {
      const user_id = 'ad|Mozilla-LDAP|foo';
      const user = handler.userFromProfile({
        email: 'foo@mozilla.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'ad', connection: 'Mozilla-LDAP'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
      assertRoles(user, ['everybody']);
    });

    test('user for email profile', function() {
      const user_id = 'email|foo';
      const user = handler.userFromProfile({
        email: 'foo@bar.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'email', connection: 'email'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
      assertRoles(user, ['everybody']);
    });

    test('user for google profile', function() {
      const user_id = 'google|foo';
      const user = handler.userFromProfile({
        email: 'foo@bar.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'google-oauth2', connection: 'google-oauth2'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
      assertRoles(user, ['everybody']);
    });

    test('user for github profile', function() {
      const user_id = 'github|0000';
      const user = handler.userFromProfile({
        nickname: 'octocat',
        user_id,
        identities: [{provider: 'github', connection: 'github'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}|octocat`);
      assertRoles(user, ['everybody']);
    });

    test('user with user_id for which encoding is not identity', function() {
      ['abc@gmail.com|0000|test', 'abc@gmail.com|0000%2F|test']
        .forEach(user_id => {
          const user = handler.userFromProfile({
            email: 'abc@gmail.com',
            email_verified: true,
            user_id,
            identities: [{provider: 'google-oauth2', connection: 'google-oauth2'}],
          });

          assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
          assertRoles(user, ['everybody']);
        });
    });

    test('user with associated groups in profile.groups', function() {
      const user_id = 'github|0000';
      const user = handler.userFromProfile({
        nickname: 'octocat',
        user_id,
        identities: [{provider: 'github', connection: 'github'}],
        groups: ['mozilliansorg_somegroup', 'some_ldap_group', 'hris_ignored'],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}|octocat`);
      assertRoles(user, ['everybody', 'mozilla-group:some_ldap_group', 'mozillians-group:somegroup']);
    });

    test('user with associated groups in profile.app_metadata.groups', function() {
      const user_id = 'github|0000';
      const user = handler.userFromProfile({
        nickname: 'octocat',
        user_id,
        identities: [{provider: 'github', connection: 'github'}],
        app_metadata: {
          groups: ['mozilliansorg_somegroup', 'some_ldap_group', 'hris_ignored'],
        },
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}|octocat`);
      assertRoles(user, ['everybody', 'mozilla-group:some_ldap_group', 'mozillians-group:somegroup']);
    });
  });

  secrets.mockSuite('profileFromUserId', ['auth0'], function(mock, skipping) {
    let handler;

    setup(function() {
      if (mock) {
        testUserId = 'mock|user';

        handler = new Handler({
          name: 'mozilla-auth0',
          cfg: {
            handlers: {
              'mozilla-auth0': {
                domain:'login-test.taskcluster.net',
                apiAudience: 'login-test.taskcluster.net',
                clientId: 'abcd',
                clientSecret: 'defg',
              },
            },
          },
        });

        // set up a simple fake management api
        handler.getManagementApi = () => ({
          getUser: (userId, cb) => {
            if (userId === testUserId) {
              cb(null, {
                app_metadata: {
                  groups: ['test-group'],
                },
              });
            } else {
              cb(new Error('no such user'));
            }
          },
        });
      } else {
        const auth0Secrets = secrets.get('auth0');
        testUserId = auth0Secrets.AUTH0_TEST_USER_ID;

        handler = new Handler({
          name: 'mozilla-auth0',
          cfg: {
            handlers: {
              'mozilla-auth0': {
                domain: auth0Secrets.AUTH0_DOMAIN,
                apiAudience: auth0Secrets.AUTH0_API_AUDIENCE,
                clientId: auth0Secrets.AUTH0_CLIENT_ID,
                clientSecret: auth0Secrets.AUTH0_CLIENT_SECRET,
              },
            },
          },
        });
      }
    });

    test('gets a profile', async function() {
      const prof = await handler.profileFromUserId(testUserId);
      assume(prof.app_metadata).to.deeply.equal({groups: ['test-group']});
    });

    test('fails if no such profile', async function() {
      await assume(handler.profileFromUserId('myspace|jbieber')).throwsAsync();
    });
  });
});

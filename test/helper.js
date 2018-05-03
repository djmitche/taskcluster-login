const taskcluster = require('taskcluster-client');
const {stickyLoader, fakeauth, Secrets} = require('taskcluster-lib-testing');
const api = require('../src/api');
const load = require('../src/main');
const config = require('taskcluster-lib-config');
const _ = require('lodash');

var helper = module.exports = {};

helper.load = stickyLoader(load);
helper.load.inject('profile', 'test');
helper.load.inject('process', 'test');

/**
 * Set up an API server.
 *
 * This also sets up helper.login as an API client, using scopes configurable
 * with helper.scopes([..]); and configures fakeAuth to support that.
 */
helper.withServer = function() {
  var webServer = null;

  // Setup before tests
  suiteSetup(async () => {
    fakeauth.start({
      'test-client': ['*'],
    });

    webServer = await helper.load('server');

    // Create client for working with API
    helper.baseUrl = 'http://localhost:' + webServer.address().port + '/v1';
    var reference = api.reference({baseUrl: helper.baseUrl});
    helper.Login = taskcluster.createClient(reference);
    // Utility to create an Login instance with limited scopes
    helper.scopes = (...scopes) => {
      helper.login = new helper.Login({
        // Ensure that we use global agent, to avoid problems with keepAlive
        // preventing tests from exiting
        agent:            require('http').globalAgent,
        baseUrl:          helper.baseUrl,
        credentials: {
          clientId:       'test-client',
          accessToken:    'none',
        },
        authorizedScopes: scopes.length > 0 ? scopes : undefined,
      });
    };
  });

  // Setup before each test
  setup(async () => {
    // Setup client with all scopes
    helper.scopes();
  });

  // Cleanup after tests
  suiteTeardown(async () => {
    // Kill webServer
    if (webServer) {
      await webServer.terminate();
    }
    fakeauth.stop();
  });
};

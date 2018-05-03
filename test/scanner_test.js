const taskcluster = require('taskcluster-client');
const assume = require('assume');
const {filter, cloneDeep} = require('lodash');
const {load} = require('./helper');

suite('scanner_test.js', function() {
  // this suite only uses a mocked auth, since the actual auth service does
  // not have a stable set of clients to scan.

  let clients = [];
  let listClientcalls = [];
  let auth;

  suiteSetup(function() {
    load.save();
    auth = new taskcluster.Auth({
      fake: {
        listClients: (args) => {
          // see https://github.com/taskcluster/taskcluster-client/pull/93
          listClientsCalls.push(cloneDeep(args));
          // test the continuationToken-handling
          const remainingClients = 'continuationToken' in args ?
            filter(clients, c => c.clientId > args.continuationToken) : clients;
          if (remainingClients.length > 1) {
            return {
              clients: [remainingClients[0]],
              continuationToken: remainingClients[0].clientId,
            };
          }
          return {
            clients: remainingClients.length ? [remainingClients[0]] : [],
          };
        },
        expandScopes: ({scopes}) => ({
          scopes: scopes.concat(scopes.map(s => s.replace('assume', 'expanded'))),
        }),
        disableClient: ({clientId}) => null,
      },
    });
    load.inject('auth', auth);
  });

  suiteTeardown(function() {
    load.restore();
  });

  setup(function() {
    clients = [];
    listClientsCalls = [];
  });

  teardown(function() {
    load.remove('scanner');
  });

  test('calls listClients with the appropriate prefix', async function() {
    clients = [
      {clientId: 'test/abc/123', expandedScopes: []},
      {clientId: 'test/abc/456', expandedScopes: []},
      {clientId: 'test/def/123', expandedScopes: []},
    ];
    await load('scanner');
    assume(listClientsCalls).to.deep.equal([
      {prefix: 'test/'},
      {continuationToken: 'test/abc/123', prefix: 'test/'},
      {continuationToken: 'test/abc/456', prefix: 'test/'},
    ]);
  });

  test('disables clients with scopes exceeding thsoe of the user', async function() {
    // user scopes are 
    //   assume:test:<identityId>
    //   expanded:test:<identityId>
    //   assume:login-identity:<identity>
    //   expanded:login-identity:<identity>
    clients = [
      {clientId: 'test/abc/123', expandedScopes: ['expanded:test:abc']},
      {clientId: 'test/abc/456', expandedScopes: ['not-held']},
      {clientId: 'test/def/123', expandedScopes: ['not-held']},
    ];
    await load('scanner');
    assume(auth.fakeCalls.disableClient).to.deep.equal([
      {clientId: 'test/abc/456'},
      {clientId: 'test/def/123'},
    ]);
  });
});

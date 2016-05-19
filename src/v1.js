import API from 'taskcluster-lib-api'
import User from './user'
import _ from 'lodash'
import taskcluster from 'taskcluster-client'

var api = new API({
  title:         "Login API",
  description:   [
    "The Login service serves as the interface between external authentication",
    "systems and TaskCluster credentials.  It acts as the server side of",
    "https://tools.taskcluster.net.  If you are working on federating logins",
    "with TaskCluster, this is probably *not* the service you are looking for.",
    "Instead, use the federated login support in the tools site.",
    "",
    "The API methods described here issue temporary credentials based on",
    "an assertion.  The assertion identifies the user, usually with an",
    "email-like string.  This string is then passed through a series of",
    "authorizers, each of which may supply scopes to be included in the",
    "credentials. Finally, the service generates temporary credentials based",
    "on those scopes.",
    "",
    "The generated credentials include scopes to create new, permanent clients",
    "with names based on the user's identifier.  These credentials are",
    "periodically scanned for scopes that the user does not posess, and disabled",
    "if such scopes are discovered.  Thus users can create long-lived credentials",
    "that are only usable until the user's access level is reduced.",
  ].join('\n'),
  schemaPrefix:  'http://schemas.taskcluster.net/login/v1/',
  context: ['authorizer', 'personaVerifier', 'temporaryCredentials'],
});

// Export api
module.exports = api;

api.declare({
  method:     'post',
  route:      '/persona',
  name:       'credentialsFromPersonaAssertion',
  idempotent: false,
  input:      'persona-request.json',
  output:     'credentials-response.json',
  title:      'Get TaskCluster credentials given a Persona assertion',
  stability:  API.stability.experimental,
  description: [
    "Given an [assertion](https://developer.mozilla.org/en-US/Persona/" +
    "Quick_setup), return an appropriate set of temporary credentials.",
    "",
    "The supplied audience must be on a whitelist of TaskCluster-related",
    "sites configured in the login service.  This is not a general-purpose",
    "assertion-verification service!",
  ].join('\n')
}, async function(req, res) {
  // verify the assertion with the persona service
  let email;
  try {
    email = await this.personaVerifier.verify(req.body.assertion, req.body.audience);
  } catch(err) {
    // translate PersonaErrors into 400's; everything else is a 500
    if (err.code == "PersonaError") {
      return res.status(400).json(err);
    }
    throw err;
  }

  // create and authorize a User
  let user = new User();
  user.identity = 'persona/' + email;
  this.authorizer.authorize(user);

  // create and return temporary credentials
  let credentials = user.createCredentials(this.temporaryCredentials);
  return res.status(200).json(credentials);
});

api.declare({
  method:     'post',
  route:      '/restrictedCredentials',
  name:       'restrictedCredentials',
  idempotent: false,
  scopes:     [
    ['auth:create-client:<newClientId>', 'login:extend-temp-credentials'],
  ],
  input:      'restricted-credentials-request.json',
  output:     'credentials-response.json',
  title:      'Get TaskCluster credentials with a subset of the caller\'s scopes',
  stability:  API.stability.experimental,
  description: [
    "This method returns a new set of temporary credentials with scopes that",
    "are satisfied, but may be smaller, than the caller.  This is useful for",
    "handing limited credentials to a less-trusted service, for example in",
    "a federated login system.",
    "",
    "The clientId of the new temporary credentials will be constructed from",
    "the caller's clientId, concatenated with the provided suffix.",
    "The caller must have scope `auth:create-client:<newClientId>`."
  ].join('\n')
}, async function(req, res) {
  let scopes = req.body.scopes;
  let newClientId = (await req.clientId()) + '/' + req.body.clientIdSuffix;

  // make sure the desired scopes are completely satisfied, and that the caller
  // can create the given clientId
  if (!req.satisfies([scopes]) || !req.satisfies({clientId: newClientId})) {
    return;
  }

  let credentials = taskcluster.createTemporaryCredentials({
    clientId: newClientId,
    start: taskcluster.fromNow(this.temporaryCredentials.startOffset),
    // XXX: expiry must be no later than the caller's credentials' expiration
    //expiry: taskcluster.fromNow(this.temporaryCredentials.expiry),
    scopes,
    credentials: this.temporaryCredentials.credentials
  });
  return res.status(200).json(credentials);
});

api.declare({
  method: 'get',
  route: '/ping',
  name: 'ping',
  title: 'Ping Server',
  stability:  API.stability.experimental,
  description: [
    'Documented later...',
    '',
    '**Warning** this api end-point is **not stable**.',
  ].join('\n'),
}, function (req, res) {
  res.status(200).json({
    alive: true,
    uptime: process.uptime(),
  });
});


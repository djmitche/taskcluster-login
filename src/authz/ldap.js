var Promise = require('promise');
var assert = require('assert');
var LDAPClient = require('./../ldap');
var debug = require('debug')('LDAPAuthorizer');

/* Determine appropriate roles based on Mozilla LDAP group membership */
class LDAPAuthorizer {
  /**
   * Create LDAP authorizer
   *
   * config (options.cfg.ldap):
   *   url:           // LDAP server
   *   cert:          // Client side certificate
   *   key:           // Client side key (for certificate)
   *   user:          // Bind user
   *   password:      // Password for bind user
   *   allowedGroups: // groups to reflect into roles
   */
  constructor(options) {
    assert(options, 'options are required');
    assert(options.cfg, 'options.cfg is required');
    assert(options.cfg.ldap, 'options.cfg.ldap is required');
    assert(options.cfg.ldap.url, 'options.cfg.ldap.url is required');
    assert(options.cfg.ldap.cert, 'options.cfg.ldap.cert is required');
    assert(options.cfg.ldap.key, 'options.cfg.ldap.key is required');
    assert(options.cfg.ldap.user, 'options.cfg.ldap.user is required');
    assert(options.cfg.ldap.password, 'options.cfg.ldap.password is required');
    assert(options.cfg.ldap.allowedGroups, 'options.cfg.ldap.allowedGroups is required');

    this.user = options.cfg.ldap.user;
    this.password = options.cfg.ldap.password;
    this.client = new LDAPClient(options.cfg.ldap);
    this.allowedGroups = options.cfg.ldap.allowedGroups;
  }

  async setup() {
  }

  async authorize(user) {
    // only trust ldap-authenticated identities
    if (user.identityProviderId !== "mozilla-ldap") {
      return;
    }
    let email = user.identityId;

    debug(`ldap authorizing ${user.identity}`);

    // always perform a bind, in case the client has disconnected
    // since this connection was last used.
    await this.client.bind(this.user, this.password);

    let addRolesForQuery = (res) => {
      return new Promise((accept, reject) => {
        res.on('searchEntry', entry => {
          let group = entry.object.cn;
          debug("..found", group);
          if (this.allowedGroups.indexOf(group) !== -1) {
            user.addRole('mozilla-group:' + group);
          }
        });
        res.on('error', reject);
        res.on('end', result => {
          if (result.status !== 0) {
            return reject(new Error('LDAP error, got status: ' + result.status));
          }
          return accept();
        });
      });
    };

    debug(`enumerating posix groups for ${email}`);
    await addRolesForQuery(await this.client.search(
      "dc=mozilla", {
      scope: 'sub',
      filter: '(&(objectClass=posixGroup)(memberUid=' + email + '))',
      attributes: ['cn'],
      timeLimit: 10,
    }));

    let userDn = await this.client.dnForEmail(email);
    if (!userDn) {
      debug(`no user found for ${email}; skipping LDAP groups`);
      return;
    }

    debug(`enumerating LDAP groups for ${userDn}`);
    await addRolesForQuery(await this.client.search(
      "dc=mozilla", {
      scope: 'sub',
      filter: '(&(objectClass=groupOfNames)(member=' + userDn + '))',
      attributes: ['cn'],
      timeLimit: 10,
    }));
  }
};

module.exports = LDAPAuthorizer;

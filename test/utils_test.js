const assume = require('assume');
const {encode, decode} = require('../src/utils');

suite('utils', function() {
  suite('encoding', () => {
    test('encode does not encode the pipe symbol', () => {
      const result = encode('ad|Mozilla-LDAP|haali');

      assume(result).to.equal('ad|Mozilla-LDAP|haali');
    });

    test('encode encodes % to !', () => {
      const result = encode('ad|Mozilla-LDAP|^haali^');

      assume(result).to.equal('ad|Mozilla-LDAP|!5Ehaali!5E');
    });
  });

  suite('decoding', () => {
    test('decode works with no special characters', () => {
      const str = 'ad|Mozilla-LDAP|haali';
      const encoded = encode(str);

      assume(decode(encoded)).to.equal(str);
    });

    test('decode works with special characters', () => {
      const str = 'ad|Mozilla-LDAP|^haali^';
      const encoded = encode(str);

      assume(decode(encoded)).to.equal(str);
    });
  });

  suite('encode/decode', () => {
    const roundTrip = (name, decoded, encoded) => {
      test(name, function() {
        assume(encode(decoded)).to.equal(encoded);
        assume(decode(encoded)).to.equal(decoded);
      });
    };

    roundTrip('simple string', 'abc', 'abc');
    roundTrip('string with all legal client punctuation characters except / does not get encoded',
      '@:.+|_-', '@:.+|_-');
    roundTrip('string with /', 'a/b/c', 'a!2Fb!2Fc');
    roundTrip('string with ~ (not legal in clientId)', 'a~z', 'a!2Fbz');
    roundTrip('string with !', 'wow!!', 'wow!21!21');
    roundTrip('already-encoded', encode('wow!!'), encode('wow!21!21'));
  });
});

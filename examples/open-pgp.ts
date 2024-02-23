import * as openpgp from 'openpgp'

console.log(`[Open PGP] Hello World!`)
console.log({openpgp})

const keyPair = await openpgp.generateKey({
  userIDs: [{name: 'Jon Smith', email: 'john@example.com'}],
  rsaBits: 2048,
  passphrase: 'super long and hard to guess secret',
})

console.log({keyPair})

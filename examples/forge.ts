import forge from 'node-forge'

console.log(`[Forge] Hello World!`)
console.log({forge})

const keyPair = forge.pki.rsa.generateKeyPair({bits: 2048})

console.log({keyPair})

import {
    createMessage,
    decrypt,
    decryptKey,
    encrypt,
    generateKey,
    readKey,
    readMessage,
    readPrivateKey,
    sign,
    verify,
} from "openpgp";

type UserData = { name: string; email: string };

// GENERATE ASYMMETRIC KEYS
export const generatePublicPrivateKeyPair = async (
    userData: UserData[],
    passphrase?: string
) => {
    const { privateKey, publicKey, revocationCertificate } = await generateKey({
        userIDs: userData,
        passphrase,
        type: "ecc", // default
        format: "armored", // default
    });

    return { privateKey, publicKey, revocationCertificate };
};

// GENERATE SYMMETRIC KEY
export const generateSymmetricKey = async () => {
    return "super long and hard to guess password";
    // return generateSessionKey({ encryptionKeys: [] });
};

// ENCRYPT SYMMETRIC KEY
export const encryptSymmetricKey = async ({
    symmetricKey,
    armoredPublicKey,
}: {
    symmetricKey: string;
    armoredPublicKey: string;
}) => {
    const publicKey = await readKey({ armoredKey: armoredPublicKey });
    const encryptedSK = await encrypt({
        message: await createMessage({ text: symmetricKey }),
        encryptionKeys: publicKey,
    });

    return encryptedSK as string;
};

// DECRYPT SYMMETRIC KEY
export const decryptSymmetricKey = async ({
    armoredEncryptedSymmetricKey,
    armoredPrivateKey,
    passphrase,
}: {
    armoredEncryptedSymmetricKey: string;
    armoredPrivateKey: string;
    passphrase: string;
}) => {
    const privateKey = await decryptPrivateKey(armoredPrivateKey, passphrase);

    const encryptedSymmetricKey = await readMessage({
        armoredMessage: armoredEncryptedSymmetricKey,
    });

    const { data } = await decrypt({
        message: encryptedSymmetricKey,
        decryptionKeys: privateKey,
    });

    return data as string;
};

// DECRYPT PRIVATE KEY
export const decryptPrivateKey = async (
    armoredPrivateKey: string,
    passphrase?: string
) => {
    return decryptKey({
        privateKey: await readPrivateKey({
            armoredKey: armoredPrivateKey,
        }),
        passphrase,
    });
};

// SIGN MESSAGE
export const createAndSignMessage = async ({
    text,
    armoredPrivateKeyForSigning,
    passphrase,
}: {
    text: string;
    armoredPrivateKeyForSigning: string;
    passphrase?: string;
}) => {
    const privateKey = await decryptPrivateKey(
        armoredPrivateKeyForSigning,
        passphrase
    );

    const unsignedMessage = await createMessage({ text });

    const armoredSignedMessage = await sign({
        message: unsignedMessage, // CleartextMessage or Message object
        signingKeys: privateKey,
    });

    return armoredSignedMessage as string;
};

// VERIFY SIGNATURE
export const verifyMessageSignature = async ({
    armoredMessage,
    armoredPublicKeyForVerifying,
}: {
    armoredMessage: string;
    armoredPublicKeyForVerifying: string;
}) => {
    const publicKey = await readKey({
        armoredKey: armoredPublicKeyForVerifying,
    });

    const message = await readMessage({
        armoredMessage: armoredMessage,
    });

    try {
        const { signatures } = await verify({
            message,
            verificationKeys: publicKey,
            expectSigned: true,
        });

        const { verified } = signatures[0];
        await verified; // throws on invalid signature
    } catch (e) {
        const error = e as Error;
        throw new Error("Signature could not be verified: " + error.message);
    }
};

// ENCRYPT
export const encryptAndSign = async ({
    text,
    symmetricKey,
    armoredPrivateKeyForSigning,
    passphrase,
}: {
    text: string;
    symmetricKey: string;
    armoredPrivateKeyForSigning?: string;
    passphrase?: string;
}) => {
    const privateKey = armoredPrivateKeyForSigning
        ? await decryptPrivateKey(armoredPrivateKeyForSigning, passphrase)
        : undefined;

    const armoredEncryptedMessage = await encrypt({
        message: await createMessage({ text }),
        passwords: symmetricKey,
        signingKeys: privateKey,
    });

    return armoredEncryptedMessage as string;
};

// DECRYPT
export const decryptAndVerifySignature = async ({
    armoredMessage,
    armoredPublicKeyForVerifying,
    symmetricKey,
}: {
    armoredMessage: string;
    armoredPublicKeyForVerifying?: string;
    symmetricKey: string;
}) => {
    const message = await readMessage({ armoredMessage });
    const publicKey = armoredPublicKeyForVerifying
        ? await readKey({
              armoredKey: armoredPublicKeyForVerifying,
          })
        : undefined;

    try {
        const { data, signatures = [] } = await decrypt({
            message,
            verificationKeys: publicKey,
            passwords: symmetricKey,
            expectSigned: !!publicKey,
        });

        const { verified } = signatures[0] ?? {};
        await verified; // throws on invalid signature
        return data as string;
    } catch (e) {
        const error = e as Error;
        throw new Error("Signature could not be verified: " + error.message);
    }
};

/****************************************************/
/*************************DEMO***********************/
/****************************************************/

/*********************************************/
/*[LEADER]: GENERATES PRIVATE-PUBLIC KEY PAIR*/
/*********************************************/

const leaderPassphrase = "super long and hard to guess secret";
const { privateKey: leaderPrivateKey, publicKey: leaderPublicKey } =
    await generatePublicPrivateKeyPair(
        [{ name: "John Smith", email: "john@example.com" }],
        leaderPassphrase
    );

/*****************************/
/*[LEADER]: STORES PUBLIC KEY*/
/*****************************/

/*********************************/
/*[USER]: GENERATES SYMMETRIC KEY*/
/*********************************/

const symmetricKey = await generateSymmetricKey();
console.log("Symmetric Key:", symmetricKey);

/**********************************/
/*[USER]: ENCRYPTS MESSAGE WITH SK*/
/**********************************/

const message = "Hello World";
const encryptedMessage = await encryptAndSign({
    text: message,
    symmetricKey,
});
console.log("Original message:", message);

/**********************************************/
/*[USER]: ENCRYPTS SK WITH LEADER'S PUBLIC KEY*/
/**********************************************/

const encryptedSK = await encryptSymmetricKey({
    symmetricKey,
    armoredPublicKey: leaderPublicKey,
});

/**************************************************/
/*[USER]: SENDS ENCRYPTED MESSAGE AND ENCRYPTED SK*/
/**************************************************/

console.log("Encrypted message:", encryptedMessage);
console.log("Encrypted Symmetric Key:", encryptedSK);

/****************************************/
/*[LEADER]: DECRYPTS SK WITH PRIVATE KEY*/
/****************************************/

const decryptedSK = await decryptSymmetricKey({
    armoredEncryptedSymmetricKey: encryptedSK,
    armoredPrivateKey: leaderPrivateKey,
    passphrase: leaderPassphrase,
});
console.log("Decrypted Symmetric Key:", decryptedSK);

/************************************/
/*[LEADER]: DECRYPTS MESSAGE WITH SK*/
/************************************/

const decryptedMessage = await decryptAndVerifySignature({
    armoredMessage: encryptedMessage,
    symmetricKey: decryptedSK,
});
console.log("Decrypted message:", decryptedMessage);

/**********************************/
/*[LEADER]: ENCRYPTS REPLY WITH SK*/
/**********************************/

const replyMessage = "Hello Anonymous";
const encryptedReplyMessage = await encryptAndSign({
    text: replyMessage,
    symmetricKey: decryptedSK,
    armoredPrivateKeyForSigning: leaderPrivateKey,
    passphrase: leaderPassphrase,
});
console.log("Original reply message:", replyMessage);

/*********************************/
/*[LEADER]: SENDS ENCRYPTED REPLY*/
/*********************************/

console.log("Encrypted reply message:", encryptedReplyMessage);

/********************************/
/*[USER]: DECRYPTS REPLY WITH SK*/
/********************************/

// const { publicKey: newPublicKey } = await generatePublicPrivateKeyPair(
//     [{ name: "John Paul II", email: "john@example.com" }],
//     leaderPassphrase
// );

const decryptedReplyMessage = await decryptAndVerifySignature({
    armoredMessage: encryptedReplyMessage,
    symmetricKey,
    armoredPublicKeyForVerifying: leaderPublicKey,
    // armoredPublicKeyForVerifying: newPublicKey,
});
console.log("Decrypted reply message:", decryptedReplyMessage);

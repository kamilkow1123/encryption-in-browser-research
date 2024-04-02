import {
    SessionKey,
    createMessage,
    decrypt,
    decryptKey,
    decryptSessionKeys,
    encrypt,
    encryptSessionKey,
    generateKey,
    generateSessionKey,
    readKey,
    readMessage,
    readPrivateKey,
    sign,
    verify,
} from "openpgp";

export type UserData = { name: string; email: string };
export type SymmetricKey = SessionKey;

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
export const generateSymmetricKey = async (): Promise<SymmetricKey> => {
    return generateSessionKey({ encryptionKeys: [] });
};

// ENCRYPT SYMMETRIC KEY
export const encryptSymmetricKey = async ({
    symmetricKey,
    armoredPublicKey,
}: {
    symmetricKey: SymmetricKey;
    armoredPublicKey: string;
}) => {
    const publicKey = await readKey({ armoredKey: armoredPublicKey });

    const { data, algorithm } = symmetricKey;
    const encryptedSK = await encryptSessionKey({
        data,
        algorithm,
        encryptionKeys: publicKey,
        format: "armored",
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

    const [decryptedSymmetricKey] = await decryptSessionKeys({
        message: encryptedSymmetricKey,
        decryptionKeys: privateKey,
    });

    return decryptedSymmetricKey;
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
        throw new Error(error.message);
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
    symmetricKey: SymmetricKey;
    armoredPrivateKeyForSigning?: string;
    passphrase?: string;
}) => {
    const privateKey = armoredPrivateKeyForSigning
        ? await decryptPrivateKey(armoredPrivateKeyForSigning, passphrase)
        : undefined;

    const armoredEncryptedMessage = await encrypt({
        message: await createMessage({ text }),
        sessionKey: symmetricKey,
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
    symmetricKey: SymmetricKey;
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
            sessionKeys: symmetricKey,
            expectSigned: !!publicKey,
        });

        const { verified } = signatures[0] ?? {};
        await verified; // throws on invalid signature
        return data as string;
    } catch (e) {
        const error = e as Error;
        throw new Error(error.message);
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
console.log("🚀 ~ leaderPublicKey:", leaderPublicKey);

/*********************************************/
/*[USER]: GENERATES PRIVATE-PUBLIC KEY PAIR*/
/*********************************************/

const userPassphrase = "super long and hard to guess secret";
const { privateKey: userPrivateKey, publicKey: userPublicKey } =
    await generatePublicPrivateKeyPair(
        [{ name: "Anonymous", email: "anonymous@example.com" }],
        userPassphrase
    );

/************************************/
/*[LEADER & USER]: STORES PUBLIC KEY*/
/************************************/

/*********************************/
/*[USER]: GENERATES SYMMETRIC KEY*/
/*********************************/

const symmetricKey = await generateSymmetricKey();
console.log("Symmetric Key:", symmetricKey);

/********************************************/
/*[USER]: ENCRYPTS AND SIGNS MESSAGE WITH SK*/
/********************************************/

const message = "Hello World Session Key Per Message";
const encryptedMessage = await encryptAndSign({
    text: message,
    symmetricKey,
    armoredPrivateKeyForSigning: userPrivateKey,
    passphrase: userPassphrase,
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
    armoredPublicKeyForVerifying: userPublicKey,
    symmetricKey: decryptedSK,
});
console.log("Decrypted message:", decryptedMessage);

/**************************/
/*[LEADER]: CREATES NEW SK*/
/**************************/

const newSymmetricKey = await generateSymmetricKey();
console.log("New Symmetric Key:", newSymmetricKey);

/**************************************/
/*[LEADER]: ENCRYPTS REPLY WITH NEW SK*/
/**************************************/

const replyMessage = "Hello Anonymous Session Key Per Message";
const encryptedReplyMessage = await encryptAndSign({
    text: replyMessage,
    symmetricKey: newSymmetricKey,
    armoredPrivateKeyForSigning: leaderPrivateKey,
    passphrase: leaderPassphrase,
});
console.log("Original reply message:", replyMessage);

/**********************************************/
/*[LEADER]: ENCRYPTS SK WITH USER'S PUBLIC KEY*/
/**********************************************/

const newEncryptedSK = await encryptSymmetricKey({
    symmetricKey: newSymmetricKey,
    armoredPublicKey: userPublicKey,
});

/******************************************************/
/*[LEADER]: SENDS ENCRYPTED REPLY AND NEW ENCRYPTED SK*/
/******************************************************/

console.log("Encrypted reply message:", encryptedReplyMessage);
console.log("New encrypted Symmetric Key:", newEncryptedSK);

/****************************************/
/*[USER]: DECRYPTS SK WITH PRIVATE KEY*/
/****************************************/

const newDecryptedSK = await decryptSymmetricKey({
    armoredEncryptedSymmetricKey: newEncryptedSK,
    armoredPrivateKey: userPrivateKey,
    passphrase: userPassphrase,
});
console.log("New decrypted Symmetric Key:", newDecryptedSK);

/********************************/
/*[USER]: DECRYPTS REPLY WITH NEW SK*/
/********************************/

const decryptedReplyMessage = await decryptAndVerifySignature({
    armoredMessage: encryptedReplyMessage,
    symmetricKey: newDecryptedSK,
    armoredPublicKeyForVerifying: leaderPublicKey,
});
console.log("Decrypted reply message:", decryptedReplyMessage);

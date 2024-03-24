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
const generatePublicPrivateKeyPair = async (
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

// DECRYPT PRIVATE KEY
const decryptPrivateKey = async (
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
const createAndSignMessage = async ({
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
const verifyMessageSignature = async ({
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

    const { signatures } = await verify({
        message,
        verificationKeys: publicKey,
    });

    const { verified } = signatures[0];
    try {
        await verified; // throws on invalid signature
    } catch (e) {
        const error = e as Error;
        throw new Error("Signature could not be verified: " + error.message);
    }
};

// ENCRYPT
const encryptAndSign = async ({
    text,
    armoredSymmetricKeyForEncrypting,
    armoredPrivateKeyForSigning,
    passphrase,
}: {
    text: string;
    armoredSymmetricKeyForEncrypting: string;
    armoredPrivateKeyForSigning?: string;
    passphrase?: string;
}) => {
    const symmetricKey = await readKey({
        armoredKey: armoredSymmetricKeyForEncrypting,
    });
    const privateKey = armoredPrivateKeyForSigning
        ? await decryptPrivateKey(armoredPrivateKeyForSigning, passphrase)
        : undefined;

    const armoredEncryptedMessage = await encrypt({
        message: await createMessage({ text }),
        encryptionKeys: symmetricKey,
        signingKeys: privateKey, // optional
    });

    return armoredEncryptedMessage as string;
};

// DECRYPT
const decryptAndVerifySignature = async ({
    armoredMessage,
    armoredPublicKeyForVerifying,
    armoredSymmetricKeyForDecrypting,
}: {
    armoredMessage: string;
    armoredPublicKeyForVerifying?: string;
    armoredSymmetricKeyForDecrypting: string;
}) => {
    const message = await readMessage({ armoredMessage });
    const publicKey = armoredPublicKeyForVerifying
        ? await readKey({
              armoredKey: armoredPublicKeyForVerifying,
          })
        : undefined;

    const privateKey = await decryptPrivateKey(
        armoredSymmetricKeyForDecrypting,
        passphrase
    );

    const { data, signatures } = await decrypt({
        message,
        verificationKeys: publicKey,
        decryptionKeys: privateKey,
        expectSigned: true,
    });

    const { verified } = signatures[0];
    try {
        await verified; // throws on invalid signature
        return data as string;
    } catch (e) {
        const error = e as Error;
        throw new Error("Signature could not be verified: " + error.message);
    }
};

/*********************/
/********DEMO*********/
/*********************/

// SIGN AND VERIFY MESSAGE
const signAndVerifyMessage = async (
    message: string,
    armoredPublicKey: string,
    armoredPrivateKey: string,
    passphrase?: string
) => {
    const signedMessage = await createAndSignMessage({
        text: message,
        armoredPrivateKeyForSigning: armoredPrivateKey,
        passphrase,
    });

    await verifyMessageSignature({
        armoredMessage: signedMessage,
        armoredPublicKeyForVerifying: armoredPublicKey,
    });
};

// ENCRYPT AND DECRYPT STRING DATA
const encryptAndDecryptMessage = async (
    text: string,
    armoredPublicKey: string,
    armoredPrivateKey: string,
    passphrase?: string
) => {
    const armoredEncryptedMessage = await encryptAndSign({
        text,
        armoredSymmetricKeyForEncrypting: armoredPublicKey,
        armoredPrivateKeyForSigning: armoredPrivateKey,
        passphrase,
    });
    console.log("🚀 ~ armoredEncryptedMessage:", armoredEncryptedMessage);

    const decryptedMessage = await decryptAndVerifySignature({
        armoredMessage: armoredEncryptedMessage,
        armoredPublicKeyForVerifying: armoredPublicKey,
        armoredSymmetricKeyForDecrypting: armoredPrivateKey,
    });
    console.log("🚀 ~ decryptedMessage:", decryptedMessage);
};

const passphrase = "super long and hard to guess secret";
const { privateKey, publicKey } = await generatePublicPrivateKeyPair(
    [{ name: "John Smith", email: "john@example.com" }],
    passphrase
);

await signAndVerifyMessage("Hello", publicKey, privateKey, passphrase);

await encryptAndDecryptMessage(
    "Hello world",
    publicKey,
    privateKey,
    passphrase
);

const { 
    generateKeyPairSync, 
    randomInt,
    sign,
} = require('crypto');

const ed = require('@noble/ed25519');

// Hooks are exported as an array of hook functions that get 
// called with the appropriate plugin API context.
module.exports.templateTags = [
    {
        name: 'genKeys',
        displayName: 'Generate Signature Keypair',
        description: 'Generates Signature Keypair, saving privateKey to environment variables and returning publicKey.',
        priority: 3,
        async run (context) {
            // const { publicKey, privateKey } = generateKeyPairSync('ed25519');
            const privateKey = ed.utils.randomPrivateKey();
            const publicKey = await ed.getPublicKey(privateKey);
            const publicKeyB64 = btoa(String.fromCharCode.apply(null,publicKey));
            await context.store.setItem('pubkey', publicKeyB64);
            await context.store.setItem('privkey', Buffer.from(privateKey).toString('hex'));
            console.log(Buffer.from(privateKey).toString('hex'));
            return publicKeyB64;
        },
    },
    {
        name: 'genIK',
        displayName: 'Generate Idempotency Key',
        description: 'Sign request and returns signature',
        priority: 2,
        async run (context) {
            const ik = randomInt(1000000000, 9999999999);
            await context.store.setItem('idempotencykey', ik);
            return ik;
        }
    },
    {
        name: 'sign',
        displayName: 'Sign',
        liveDisplayName: (params) => 
            `sign{${params[0].value ? 'idempotency-key,' : ''}${params[1].value}}`,
        description: 'Sign request and returns signature',
        args: [
            {
                displayName: 'Sign With IdempotencyKey',
                description: 'Generate random number on start of signature',
                type: 'boolean',
                defaultValue: true 
            },
            {
                displayName: 'Fields',
                description: 'Comma separated body keys that will be encrypted',
                type: 'string',
                defaultValue: ''
            },
        ],
        priority: 1,
        async run (context, signWithIK, fields) {
            const request = await context.util.models.request.getById(context.meta.requestId);
            const privateKey = await context.store.getItem('privkey');
            
            let message = '';

            if (signWithIK) {
                const ik = await context.store.getItem('idempotencykey');
                message += ik.toString('utf8');
            }
            const body = JSON.parse(request.body.text);
            for (const field of fields.split(',')) {
                if (await context.store.hasItem(field)) {
                    message += await context.store.getItem(field);
                } else {
                    message += body[field].toString('utf8');
                }
            }
            let messageEncoded = new TextEncoder('utf-8').encode(message);
            const message2 = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
            return Buffer.from(await ed.sign(messageEncoded, privateKey))
                .toString('base64');
        }
    },
];


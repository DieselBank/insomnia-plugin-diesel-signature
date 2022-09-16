const { randomInt } = require('crypto');
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
            const privateKey = ed.utils.randomPrivateKey();
            const publicKey = await ed.getPublicKey(privateKey);
            const publicKeyB64 = btoa(String.fromCharCode.apply(null,publicKey));
            await context.store.setItem('pubkey', publicKeyB64);
            await context.store.setItem('privkey', Buffer.from(privateKey).toString('hex'));
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
                message += await context.store.getItem('idempotencykey');
            }
            // Getting body from json or multipart form
            let body = {};
            if (request.body.mimeType === 'application/json') {
                body = JSON.parse(request.body.text);
            } else if (request.body.mimeType === 'multipart/form-data') {
                for (const p of request.body.params) {
                    body[p.name] = p.value;
                }
            }
            // Getting field strings
            for (const field of fields.split(',')) {
                if (field[0] === '$') {
                    // If field is `$N` gets url param N
                    message += request.url.split('/')[parseInt(field.substring(1))];
                } else if (await context.store.hasItem(field)) {
                    // If field is present in store get it from there
                    message += await context.store.getItem(field);
                } else {
                    // Else get from body
                    message += body[field].toString();
                }
            }
            let messageEncoded = new TextEncoder('utf-8').encode(message);
            const message2 = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
            return Buffer.from(await ed.sign(messageEncoded, privateKey))
                .toString('base64');
        }
    },
    {
        name: 'uid',
        displayName: 'UID',
        description: 'Gets user ID returned from an endpoint',
        async run (context)  {
            return await context.store.getItem('uid');
        }
    },
    {
        name: 'transactionKey',
        displayName: 'Transaction Key',
        description: 'Gets Transaction Key returned from an endpoint',
        async run (context)  {
            return await context.store.getItem('transactionKey');
        }
    },
];

// Response hooks
module.exports.responseHooks = [
    async (context) => {
        const body = JSON.parse(context.response.getBody().toString('utf-8'));
        if (body.uid) {
            await context.store.setitem('uid', body.uid);
        }
        if (body.transactionKey) {
            await context.store.setitem('transactionKey', body.uid);
        }
    },
];

import express from "express"
import { randomUUID } from "crypto"
//import { dSyncSign } from "../dSyncSign/index.mjs";


function generateRandomString(){
    return (Math.random().toString(36).slice(2)) + (Math.random().toString(36).slice(2))
}

export default class dSyncAuth {

    static encodeToBase64(jsonString) {
        return btoa(encodeURIComponent(jsonString));
    }

    static decodeFromBase64(base64String) {
        return decodeURIComponent(atob(base64String));
    }

    static generateGid(publicKey) {
        return (this.encodeToBase64(publicKey.substring(80, 120)));
    }

    constructor(app, dSyncSign, onVerify, onLogin) {
        this.authAttempts = new Map();
        this.signer = dSyncSign;

        this.onVerify = typeof onVerify === "function" ? onVerify : null;
        this.onLogin = typeof onLogin === "function" ? onLogin : null;


        if (!app) {
            console.error("Express app is required for dSyncAuth!")
            process.exit(0)
        }

        if (!dSyncSign) {
            console.error("dSyncSign is required for dSyncAuth!")
            process.exit(0)
        }


        app.use(express.json())

        // verify decrypted random string
        app.post(`/dSyncAuth/login`, express.json(), async (req, res) => {
            const { publicKey } = req.body
            const ip = req.ip || req.connection?.remoteAddress

            if (!publicKey) {
                res.status(400).json({ error: "Missing public key" })
                return
            }

            let normalizedPublicKey = await this.signer.normalizePublicKey(publicKey);
            let challengeString = generateRandomString();
            let challenge =  await this.signer.encrypt(challengeString, normalizedPublicKey);
            let identifier = dSyncAuth.generateGid(publicKey);

            let data = {
                publicKey,
                identifier,
                challenge,
                challengeString
            }

            // create challenge
            this.authAttempts.set(identifier, JSON.stringify(data));

            res.status(200).json({
                identifier,
                challenge
            })

            if(this.onLogin) this.onLogin({ challenge, publicKey })

            setTimeout(() => {
                this.authAttempts.delete(identifier);
            }, 10_000)
        })

        app.post(`/dSyncAuth/verify`, express.json(), async (req, res) => {
            const { identifier, solution, publicKey } = req.body

            if (!identifier) {
                res.status(400).json({ error: "Missing identifier" })
                return
            }

            if (!solution) {
                res.status(400).json({ error: "Missing solution" })
                return
            }

            let challenge = this.authAttempts.get(identifier) ? JSON.parse(this.authAttempts.get(identifier)) : null;

            if(challenge){
                if(challenge.challengeString === solution && publicKey === challenge.publicKey){
                    // do callback if set
                    if(this.onVerify) this.onVerify( {valid: true, identifier, solution, publicKey: challenge.publicKey} );
                    res.status(200).json({ error: null })
                    return;
                }
                else{
                    if(this.onVerify) this.onVerify( {valid: false, identifier, solution, publicKey: challenge.publicKey} );
                    res.status(403).json({ error: "Invalid solution or key" })
                    return;
                }
            }
            else{
                res.status(404).json({ error: "Challange not found" })
            }
        })
    }
}

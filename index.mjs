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

    static async createChallenge(signer, publicKey) {
        let normalizedKey = await signer.normalizePublicKey(publicKey);
        let challengeString = generateRandomString();
        let challenge = await signer.encrypt(challengeString, normalizedKey);
        let identifier = dSyncAuth.generateGid(publicKey);

        return { identifier, challenge, challengeString }
    }

    static getChallenge(authAttempts, identifier) {
        let data = authAttempts.get(identifier);
        if(!data) return null;
        return JSON.parse(data);
    }

    static verifyChallenge(authAttempts, identifier, solution, publicKey) {
        let challenge = dSyncAuth.getChallenge(authAttempts, identifier);
        if(!challenge) return { valid: false, error: "Challenge not found" }

        if(challenge.challengeString === solution && publicKey === challenge.publicKey) {
            authAttempts.delete(identifier);
            return { valid: true, publicKey: challenge.publicKey }
        }

        return { valid: false, error: "Invalid solution or key" }
    }

    static async verifyServerPublicKey(address, publicKey, signer) {
        if(!address) throw new Error("missing address");
        if(!publicKey) throw new Error("missing publicKey");
        if(!signer) throw new Error("missing signer");

        address = String(address).trim().replace(/\/+$/, "");

        const normalizedKey = await signer.normalizePublicKey(publicKey);
        const challengeString = (Math.random().toString(36).slice(2)) + (Math.random().toString(36).slice(2));
        const challenge = await signer.encrypt(challengeString, normalizedKey);

        const res = await fetch(`${address}/dSyncAuth/challenge`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ challenge })
        });

        let data = null;
        try {
            data = await res.json();
        } catch {}

        if(!res.ok) throw new Error(data?.error || "challenge request failed");
        if(!data?.solution) throw new Error("no solution returned");
        if(!data?.publicKey) throw new Error("no publicKey returned");

        const returnedKey = await signer.normalizePublicKey(data.publicKey);

        if(data.solution !== challengeString) throw new Error("invalid challenge solution");
        if(returnedKey !== normalizedKey) throw new Error("publicKey mismatch");

        return true;
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

        app.post(`/dSyncAuth/challenge`, express.json(), async (req, res) => {
            const { challenge } = req.body

            if(!challenge) {
                res.status(400).json({ error: "Missing challenge" })
                return
            }

            try {
                let solution = await this.signer.decrypt(challenge)
                res.status(200).json({ solution, publicKey: this.signer.publicKey })
            } catch(err) {
                res.status(400).json({ error: "Failed to solve challenge" })
            }
        })

        // verify decrypted random string
        app.post(`/dSyncAuth/login`, express.json(), async (req, res) => {
            const { publicKey } = req.body
            if(!publicKey) return res.status(400).json({ error: "Missing public key" })

            let { identifier, challenge, challengeString } = await dSyncAuth.createChallenge(this.signer, publicKey)

            let data = { publicKey, identifier, challenge, challengeString }
            this.authAttempts.set(identifier, JSON.stringify(data));
            setTimeout(() => { this.authAttempts.delete(identifier) }, 10_000)

            res.status(200).json({ identifier, challenge })
            if(this.onLogin) this.onLogin({ challenge, publicKey })
        })

        app.post(`/dSyncAuth/verify`, express.json(), async (req, res) => {
            const { identifier, solution, publicKey } = req.body
            if(!identifier) return res.status(400).json({ error: "Missing identifier" })
            if(!solution) return res.status(400).json({ error: "Missing solution" })

            let result = dSyncAuth.verifyChallenge(this.authAttempts, identifier, solution, publicKey)

            if(result.valid) {
                if(this.onVerify) this.onVerify({ valid: true, identifier, solution, publicKey: result.publicKey })
                return res.status(200).json({ error: null })
            }

            if(this.onVerify) this.onVerify({ valid: false, identifier, solution, publicKey })
            res.status(result.error === "Challenge not found" ? 404 : 403).json({ error: result.error })
        })
    }
}

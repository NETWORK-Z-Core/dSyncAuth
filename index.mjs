import express from "express"
import {randomUUID, randomBytes, createHash} from "crypto"
import DateTools from "@hackthedev/datetools"
import cors from "cors"

function generateRandomString() {
    return (Math.random().toString(36).slice(2)) + (Math.random().toString(36).slice(2))
}

export default class dSyncAuth {
    constructor(app, dSyncSign, onVerify, onLogin) {
        this.authAttempts = new Map();
        this.signer = dSyncSign;

        this.onVerify = typeof onVerify === "function" ? onVerify : null;
        this.onLogin = typeof onLogin === "function" ? onLogin : null;

        this.authSessions = new Map();

        if (!app) {
            console.error("Express app is required for dSyncAuth!")
            process.exit(0)
        }

        if (!dSyncSign) {
            console.error("dSyncSign is required for dSyncAuth!")
            process.exit(0)
        }

        const corsOptions = {
            origin: "*",
            methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allowedHeaders: ["Content-Type", "Authorization", "sessionid", "publickey"]
        }

        app.use("/dSyncAuth", cors(corsOptions))
        app.options("/dSyncAuth/*", cors(corsOptions))

        app.post(`/dSyncAuth/challenge`, express.json(), async (req, res) => {
            const {challenge} = req.body

            if (!challenge) {
                res.status(400).json({error: "Missing challenge"})
                return
            }

            try {
                let solution = await this.signer.decrypt(challenge)
                res.status(200).json({solution, publicKey: this.signer.publicKey})
            } catch (err) {
                res.status(400).json({error: "Failed to solve challenge"})
            }
        })

        // verify decrypted random string
        app.post(`/dSyncAuth/login`, express.json(), async (req, res) => {
            const {publicKey} = req.body
            if (!publicKey) return res.status(400).json({error: "Missing public key"})

            let {identifier, challenge, challengeString} = await dSyncAuth.createChallenge(this.signer, publicKey)

            let data = {publicKey, identifier, challenge, challengeString}
            this.authAttempts.set(identifier, JSON.stringify(data));
            setTimeout(() => {
                this.authAttempts.delete(identifier)
            }, 10_000)

            res.status(200).json({identifier, challenge})
            if (this.onLogin) this.onLogin({challenge, publicKey})
        })

        app.post(`/dSyncAuth/verify/session`, express.json(), async (req, res) => {
            const {sessionId, publicKey} = req.body
            if (!sessionId) return res.status(400).json({error: "Missing sessionId"})

            let result = dSyncAuth.verifySession(this.authSessions, sessionId, publicKey)

            if (!result.valid) {
                return res.status(401).json({error: "Invalid session"})
            }

            let session = dSyncAuth.getSession(this.authSessions, sessionId)

            return res.status(200).json({
                error: null,
                valid: true,
                publicKey: result.publicKey,
                expiresAt: session?.expiresAt ?? null
            })
        })

        app.post(`/dSyncAuth/verify`, express.json(), async (req, res) => {
            const {identifier, solution, publicKey} = req.body
            if (!identifier) return res.status(400).json({error: "Missing identifier"})
            if (!solution) return res.status(400).json({error: "Missing solution"})

            let result = dSyncAuth.verifyChallenge(this.authAttempts, identifier, solution, publicKey)

            if (result.valid) {
                let session = dSyncAuth.createSession(this.authSessions, result.publicKey, 24 * 30)

                if (this.onVerify) this.onVerify({
                    valid: true,
                    identifier,
                    solution,
                    publicKey: result.publicKey,
                    sessionId: session.sessionId,
                    expiresAt: session.expiresAt
                })

                return res.status(200).json({
                    error: null,
                    sessionId: session.sessionId,
                    expiresAt: session.expiresAt
                })
            }

            if (this.onVerify) this.onVerify({valid: false, identifier, solution, publicKey})
            res.status(result.error === "Challenge not found" ? 404 : 403).json({error: result.error})
        })
    }

    static createSession(authSessions, publicKey, sessionDurationHours = 24) {
        let sessionId = randomUUID();
        let createdAt = Date.now();
        let expiresAt = DateTools.getDateFromOffset("30 days").getTime();

        let data = {
            sessionId,
            publicKey,
            createdAt,
            expiresAt
        };

        authSessions.set(sessionId, JSON.stringify(data));
        return data;
    }

    static getSession(authSessions, sessionId) {
        if (!sessionId) return null;

        let data = authSessions.get(sessionId);
        if (!data) return null;

        let parsed = JSON.parse(data);
        if (!parsed?.expiresAt || parsed.expiresAt <= Date.now()) {
            authSessions.delete(sessionId);
            return null;
        }

        return parsed;
    }

    static verifySession(authSessions, sessionId, publicKey = null) {
        let session = dSyncAuth.getSession(authSessions, sessionId);
        if (!session) return {valid: false};

        if (publicKey && session.publicKey !== publicKey) {
            return {valid: false};
        }

        return {valid: true, publicKey: session.publicKey};
    }

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

        return {identifier, challenge, challengeString}
    }

    static getChallenge(authAttempts, identifier) {
        let data = authAttempts.get(identifier);
        if (!data) return null;
        return JSON.parse(data);
    }

    static verifyChallenge(authAttempts, identifier, solution, publicKey) {
        let challenge = dSyncAuth.getChallenge(authAttempts, identifier);
        if (!challenge) return {valid: false, error: "Challenge not found"}

        if (challenge.challengeString === solution && publicKey === challenge.publicKey) {
            authAttempts.delete(identifier);
            return {valid: true, publicKey: challenge.publicKey}
        }

        return {valid: false, error: "Invalid solution or key"}
    }

    static async verifyServerPublicKey(address, publicKey, signer) {
        if (!address) throw new Error("missing address");
        if (!publicKey) throw new Error("missing publicKey");
        if (!signer) throw new Error("missing signer");

        address = String(address).trim().replace(/\/+$/, "");

        const normalizedKey = await signer.normalizePublicKey(publicKey);
        const challengeString = (Math.random().toString(36).slice(2)) + (Math.random().toString(36).slice(2));
        const challenge = await signer.encrypt(challengeString, normalizedKey);

        const res = await fetch(`${address}/dSyncAuth/challenge`, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({challenge})
        });

        let data = null;
        try {
            data = await res.json();
        } catch {

        }

        if (!res.ok) throw new Error(data?.error || "challenge request failed");
        if (!data?.solution) throw new Error("no solution returned");
        if (!data?.publicKey) throw new Error("no publicKey returned");

        const returnedKey = await signer.normalizePublicKey(data.publicKey);

        if (data.solution !== challengeString) throw new Error("invalid challenge solution");
        if (returnedKey !== normalizedKey) throw new Error("publicKey mismatch");

        return true;
    }

    static isValidProof(challenge, solution, difficulty) {
        let hash = createHash("sha256").update(challenge + solution).digest("hex")
        let requiredBits = difficulty * 4
        let actualBits = dSyncAuth.countLeadingZeroBits(hash)
        return {
            level: Math.floor(actualBits / 4),
            required: Math.floor(requiredBits / 4),
            valid: actualBits >= requiredBits
        }
    }

    static countLeadingZeroBits(hash) {
        let bits = 0
        for (let char of hash) {
            let nibble = parseInt(char, 16)
            if (nibble === 0) {
                bits += 4;
                continue
            }
            if (nibble < 2) bits += 3
            else if (nibble < 4) bits += 2
            else if (nibble < 8) bits += 1
            break
        }
        return bits
    }

    static estimatePoWDuration(difficulty, hashRate = 18535) {
        let expectedTries = Math.pow(2, 4 * difficulty)
        let estimatedSeconds = Math.round(expectedTries / hashRate)
        return {hashRate, expectedTries, estimatedSeconds}
    }

    // instance methods
    createPowChallenge(difficulty) {
        let diff = difficulty || 5
        let challenge = randomBytes(16).toString("hex")
        return {challenge, difficulty: diff}
    }

    waitForPow(challenge, difficulty, timeoutSeconds) {
        let diff = difficulty || 5
        let timeout = (timeoutSeconds || 60) * 1000

        let _resolve, _reject
        let done = false

        let promise = new Promise((resolve, reject) => {
            _resolve = resolve
            _reject = reject

            setTimeout(() => {
                if (!done) {
                    done = true
                    reject(new Error("pow timeout"))
                }
            }, timeout)
        })

        promise.verify = (solution) => {
            if (done) return {valid: false, error: "expired"}

            let result = dSyncAuth.isValidProof(challenge, solution, diff)
            if (result.valid) {
                done = true
                _resolve({valid: true, challenge, solution})
                return {valid: true}
            }
            return {valid: false, level: result.level, required: result.required}
        }

        return promise
    }
}

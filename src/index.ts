import { PrismaClient } from "@prisma/client";
import express, {Express} from "express";
import session from 'express-session';
import {z} from "zod";

import SimpleWebAuthnServer, {
    generateAuthenticationOptions,
    generateRegistrationOptions, verifyAuthenticationResponse,
    verifyRegistrationResponse
} from '@simplewebauthn/server';

const rpName = "modahuro"
const rpID = 'localhost'
const origin = `http://${rpID}:25566`

declare module 'express-session' {
    interface SessionData {
        userId?: number
    }
}


const prisma = new PrismaClient()

const app:Express = express()

app.set("view engine", "ejs")

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'raccoon',
    name: 'session',
    resave: false,
    saveUninitialized: true,
    cookie: {
        path: '/',
        httpOnly: true,
        maxAge: 60/* min */ * 60/* s*/ * 1000 /*ms*/
    }
}))

app.get("/", async (req,res) => {
    if (req.session.userId) {
        const user = await prisma.user.findUnique({
            where: {
                id: req.session.userId
            }
        })
        res.render("index", {
            user: user
        });
    } else {
        res.redirect("/login")
    }
})

app.get("/login", (req, res) => {
    if (req.session.userId) {
        res.redirect("/")
    } else {
        res.render("login")
    }
})

const loginDataSchema = z.object({
    name: z.string().min(1),
    password: z.string().min(1)
})

type loginData = z.infer<typeof loginDataSchema>

app.post("/login", async (req,res) => {
    const validate = await loginDataSchema.safeParse(req.body)
    if (validate.success) {
        const loginRequest = validate.data
        prisma.user.findFirst({
            where: {
                name: loginRequest.name
            }
        }).then(user => {
            if (user) {
                if (user.password === loginRequest.password)  {
                    req.session.userId = user.id
                    res.redirect("/")
                    return
                }
            }
            res.render("login")
        }).catch(e => {
            console.error(e)
            res.render("login")
        })

    } else {
        res.render("login")
    }
})

app.get("/register", (req,res) => {
    res.render("register")
})

app.post("/register", async (req,res) => {
    const validate = await loginDataSchema.safeParse(req.body)
    if (validate.success) {
        const registerRequest = validate.data
        prisma.user.create({
            data: {
                name: registerRequest.name,
                password: registerRequest.password
            }
        }).then(() => {
            res.redirect("/")
        }).catch(() => {
            res.render("register")
        })
    } else {
        res.render("register")
    }
})

app.get("/logout", (req,res) => {
    req.session.userId = void 0
    res.redirect("/login")
})

/**
 * API
 */

app.get("/api/getRegistrationOptions", async (req,res) => {
    if (!req.session.userId) {
        res.send({
            error: "no login"
        })
        return
    }
    const user = await prisma.user.findUnique({
        where: {
            id: req.session.userId
        },
        include: {
            authenticators: true
        }
    })
    if (!user) {
        res.send({
            error: 'user not exists'
        })
        return
    }

    const options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: `${user.id}`,
        userName: user.name,
        attestationType: 'none',
        excludeCredentials: user.authenticators.map(authenticator => ({
            id: authenticator.credentialID,
            type: 'public-key',
        })),
    });

    await prisma.user.update({
        where: {
            id: user.id
        },
        data: {
            currentChallenge: options.challenge
        }
    })

    res.send(options)

})
app.get("/api/getAuthenticationOptions", async (req,res) => {
    const user = await prisma.user.findUnique({
        where: {
            name: `${req.query.name}`
        },
        include: {
            authenticators: true
        }
    })
    if (!user) {
        res.send({
            error: true
        })
        return
    }


    const options = generateAuthenticationOptions({
       allowCredentials: user.authenticators.map(authenticator => ({
           id: authenticator.credentialID,
           type: 'public-key',
       }))
    });

    await prisma.user.update({
        where: {
            id: user.id
        },
        data: {
            currentChallenge: options.challenge
        }
    })

    res.send(options)

})

app.post("/api/verification", async (req,res) => {
    const { body } = req;

    const user = await prisma.user.findUnique({
        where: {
            id: req.session.userId
        },
        include: {
            authenticators: true
        }
    })
    if (!user) {
        res.send({error: true})
        return
    }

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            credential: body,
            expectedChallenge: (user.currentChallenge ?? ""),
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
    } catch (e) {
        const error = e as any
        console.error(error);
        return res.status(400).send({ error: error.message });
    }

    const { verified } = verification;

    if (!verified) {
        res.send({error: true})
        return
    }

    const { registrationInfo } = verification;

    if (!registrationInfo) {
        res.send({error: true})
        return
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    await prisma.authenticator.create({
        data: {
            credentialID: credentialID,
            credentialPublicKey: credentialPublicKey,
            counter: counter,
            user: {
                connect: {
                    id: user.id
                }
            }
        }
    })

    res.send({
        verified
    })



})

app.post('/api/authentication', async (req, res) => {

    const requestedCredentialId = req.body.id
    const requestedCredentialIdBuffer = Buffer.from(requestedCredentialId, 'base64')

    const authenticator = await prisma.authenticator.findFirst({
        where: {
            credentialID: requestedCredentialIdBuffer
        },
        include: {
            user: true
        }
    })

    if (!authenticator ) {
        res.send({
            error: "no webauthn registration"
        })
        return
    }

    const verification = await verifyAuthenticationResponse({
        credential: req.body,
        expectedChallenge: authenticator.user.currentChallenge ?? "",
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator
    });

    const { verified } = verification;

    if (verified) {
        req.session.userId = authenticator.user.id
    }

    res.send({
        verified
    })
    if (!verified) {
        return
    }



    const { authenticationInfo } = verification;
    const { newCounter } = authenticationInfo;

    await prisma.authenticator.updateMany({
        where: {
            id: authenticator.id
        },
        data: {
            counter: newCounter
        }
    })



})

app.listen(25566, () => {
    console.log("Server Started : http://localhost:25566")
})

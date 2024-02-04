import prisma from '../../database';
import {  RequestHandler, Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import 'dotenv/config';

const router = Router();
const SECRET: string = process.env.SECRET as string;

const loggedMiddleware: RequestHandler = (req, res, next) => {
    const auth = req.headers.authorization || '';

    const parts = auth.split(' ');

    if(parts.length != 2)
        return res.status(401).send();

    const [prefix, token] = parts;

    if(prefix !== 'Bearer')
        return res.status(401).send();

    jwt.verify(token, SECRET, (error, decoded) => {
        if(error) {
            return res.status(401).send(error);
        }

        res.locals.creatorId = (decoded as jwt.JwtPayload).id;

        next();
    });
};

// user register
router.post('/register', async (req, res) => {
    const {name, email, password, role} = req.body;
    const infoNeeded = {name, email, password, role};

    if (!infoNeeded) {
        return res.status(401).send('missing fields');
    }

    const searchedUserByEmail = await prisma.user.findFirst({
        where: {
            email
        }, 
        select: {
            email: true
        }
    })

    if (searchedUserByEmail) {
        return res.status(401).send('this email is already in use');
    }

    const newUser = await prisma.user.create({
        data: {
            name,
            email,
            password: bcrypt.hashSync(password, 10),
            role
        }
    });

    const users = await prisma.user.findMany({ });

    if(role === "admin") {
        return res.status(200).send({ users });
    } else if (role === "user") {
        return res.status(200).send({ name });
    } else (!role); {
        return res.status(401).send('undefined role');
    }

});

// user login
router.post('/login', loggedMiddleware, async (req, res) => {
    const {email, password} = req.body;
    const infoNeeded = email && password;

    if (!infoNeeded) {
        return res.status(401).send('missing fields');
    }

    const user = await prisma.user.findFirst({
        where: {
            email
        },
        select: {
            id: true,
            name: true,
            password: true,
            role: true
        }
    });

    const users = await prisma.user.findMany({ });

    if (!user) {
        return res.status(401).send('please be registered');
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('the passwords are not the same');
    }

    if(user.role === "admin") {
        return res.status(200).send({ users });
    } else if (user.role === "user") {
        return res.status(200).send({ user });
    } else (!user.role); {
        return res.status(401).send('undefined role');
    }
});

// users info
router.get('/users_info', loggedMiddleware, async (req, res) => {
    const { email, password } = req.body;
    const infoNeeded = email && password;

    if (!infoNeeded) {
        return res.status(401).send('missing fields');
    }

    const users = await prisma.user.findMany({ });

    const user = await prisma.user.findFirst({
        where: {
            email
        },
        select: {
            id: true,
            name: true, 
            password: true,
            role: true
        }
    });

    if (!user) {
        return res.status(404).send('please be registered');
    }

    if (user.role == 'admin') {
        return res.status(200).send({ users });
    } else (!user.role); {
        return res.status(401).send('undefined role')
    }
});

export default router;
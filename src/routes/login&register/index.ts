import prisma from '../../database';
import {  RequestHandler, Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import 'dotenv/config';

const router = Router();
const SECRET: string = process.env.SECRET as string;

// middleware to verify login
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

    const newUser = await prisma.user.create({
        data: {
            name,
            email,
            password: bcrypt.hashSync(password, 10),
            role
        }
    });

    const usersInfo = await prisma.user.findMany({ });

    if(role === "admin") {
        return res.status(200).send({ usersInfo });
    } else if (role === "user") {
        return res.status(200).send({ name });
    } else (!role); {
        return res.status(401).send('undefined role');
    }

});

export default router;
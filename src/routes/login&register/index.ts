import prisma from '../../database';
import {  RequestHandler, Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import 'dotenv/config';

const router = Router();
const SECRET: string = process.env.SECRET as string;

// user register
router.post('/register', async (req, res) => {
    const {name, email, password} = req.body;
    const infoNeeded = {name, email, password};

    if (!infoNeeded) {
        return res.status(401).send('missing fields');
    }

    const newUser = await prisma.user.create({
        data: {
            name,
            email,
            password: bcrypt.hashSync(password, 10)
        }
    });

    const user = await prisma.user.findFirst({
        where: {
            email,
            password
        }
    });

    if (user) {
        return res.status(401).send('user already exists')
    }

    const token = jwt.sign(newUser, SECRET, {
        expiresIn: '5h'
    });

    res.status(200).send({ newUser, token });
});

// user login
router.post('/login', async (req, res) => {
    const {email, password} = req.body;
    const infoNeeded = email && password;

    if (!infoNeeded) {
        return res.status(401).send('missing fields')
    }

    const user = await prisma.user.findFirst({
        where: {
            email
        },
        select: {
            id: true,
            password: true
        }
    });

    if (!user) {
        return res.status(401).send('please be registered')
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(404).send('please try again')
    }

    const token = jwt.sign({id: user.id}, SECRET, {
        expiresIn: '5h'
    });

    res.status(200).send({ user, token });
});

export default router;
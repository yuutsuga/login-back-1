import prisma from '../../database';
import {  RequestHandler, Router } from 'express';
import jwt, { decode } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import 'dotenv/config';

const router = Router();
const SECRET: string = process.env.SECRET as string;

// middleware to verify if user has token and role is admin or not
const isAdmin: RequestHandler = async (req, res, next) => {
    const auth = req.headers.authorization || '';

    const parts = auth.split(' ');

    if (parts.length != 2) {
        return res.status(401).send();
    }

    const [prefix, token] = parts;

    if (prefix !== 'Bearer') {
        return res.status(401).send();
    }

    const userRole: any = await prisma.user.findFirst({
        where: {
            role: "Admin"
        }
    });

    jwt.verify(token, SECRET, (error, decode) => {
        if (error) {
            return res.status(401).send(error);
        }
    });
    
    if (userRole.role !== "Admin" || token === null) {
        return res.status(401).send("you're not an admin");
    }
    next();
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
        },
    });

    const users = await prisma.user.findMany({ });

    const token = jwt.sign({role: newUser.role}, SECRET, {
        expiresIn: '1h'
    })

    if(role === "Admin") {
        return res.status(200).send({ users, token });
    } else if (role === "User") {
        return res.status(200).send({ name, token });
    } else (!role); {
        return res.status(401).send('undefined role');
    }
});

// user login
router.post('/login', async (req, res) => {
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

    if(user.role === "Admin") {
        return res.status(200).send({ users });
    } else if (user.role === "User") {
        return res.status(200).send({ user });
    } else (!user.role); {
        return res.status(401).send('undefined role');
    }
});

// users info
router.get('/admin', isAdmin, async (_, res) => {

   const users = await prisma.user.findMany({
    where: {
        role: "Admin"
    },
    select: {
        name: true,
        email: true,
        password: true,
        role: true
    },
   });

   res.status(200).send({ users });
});

export default router;
import express from 'express';
import 'dotenv/config';
import morgan from 'morgan';
import loginAndRegiterRouter from './routes/login&register';

const PORT = process.env.PORT;
const app = express();

app.use(express.json());
app.use(morgan('dev'));

app.use(loginAndRegiterRouter);

app.listen(PORT, () => {
    console.log(`connected to: ${PORT}`);
});
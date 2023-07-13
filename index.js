const express = require('express');

const app = express();
const cors = require('cors');
const bcryptjs = require('bcryptjs');
app.use(express.json());
app.use(cors())
const mongodb = require('mongodb');
const mongoClient = mongodb.MongoClient;
const dotenv = require('dotenv').config();
const URL = process.env.DB;
const usermail = process.env.USER;
const mailpassword = process.env.PASSWORD
const jwt = require('jsonwebtoken');

const rn = require('random-number');
const options = {
    min: 1000,
    max: 9999,
    integer: true
}
const nodemailer = require("nodemailer");



app.get("/", function (request, response) {
    response.send("welcome to CRM 🎉🎉🎉🎉🎉");
});


//1 register
app.post('/register', async function (req, res) {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password1, salt);
        req.body.password1 = hash;
        delete req.body.password2;
        await db.collection('users').insertOne(req.body);
        await connection.close();
        res.json({ message: "User created registered successfully" })
    } catch (error) {
        console.log(error);
    }
})

//3 Login
app.post('/login', async function (req, res) {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ username: req.body.username });
        if (user) {
            const match = await bcryptjs.compare(req.body.password, user.password1);
            if (match) {
                const token = jwt.sign({ _id: user._id, name: user.username }, process.env.SECRET_KEY,);
                res.status(200).json({
                    message: 'Successfully Logged in',
                    token: token,
                    name: user.username
                })
            } else {
                res.json({ message: 'Password Incorrect' });
            }
        }
        else {
            res.json({ message: 'User not found' })
        }
    } catch (error) {
        console.log(error);
    }
})






//4 verification mail
app.post('/sendmail', async function (req, res) {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ email: req.body.email });
        if (user) {
            let randomnum = rn(options);

            await db.collection('users').updateOne({ email: req.body.email }, { $set: { rnum: randomnum } });
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                host: "smtp.gmail.com",
                secure: false,
                auth: {
                    user: `${usermail}`,
                    pass: `${mailpassword}`,
                }
            });

            var mailOptions = {
                from: 'sivatestnode@gmail.com',
                to: `${req.body.email}`,
                subject: 'User verification',
                text: `${randomnum}`,
                //html: `<h2>Password : ${req.body.Password}</h2>`
            };

            await transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                    res.json({
                        message: "Error"
                    })
                } else {
                    console.log('Email sent: ' + info.response);
                    res.json({
                        message: "Email sent"
                    })
                }
            });
        }
        else {
            res.status(400).json({ message: 'User not found' })
        }
    }
    catch (error) {
        console.log(error);
    }
})



//5 verify 

app.post("/verify", async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ email: req.body.email });
        await connection.close();
        if (user.rnum === req.body.vercode) {
            res.status(200).json(user)
        }
        else {
            res.status(400).json({ message: "Invalid Verification Code" })
        }
    } catch (error) {
        console.log(error);
    }
})


//6 update password
app.post('/changepassword/:id', async function (req, res) {
    try {

        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password1, salt);
        req.body.password1 = hash;
        delete req.body.password2;
        await db.collection('users').updateOne({ email: req.params.id }, { $set: req.body });;
        await connection.close();
        res.json({ message: "Password updated successfully" })
    } catch (error) {
        console.log(error);
    }
})


app.listen(process.env.PORT, () => console.log("mongo is running at", process.env.PORT));
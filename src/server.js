import express from 'express';
import SYSTEMCONFIG from './systemconfig.js';
import path from 'path';

const app = express();
const {MongoClient} = require('mongodb');
const JWT = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const withCookieAuth = require('./MWCookieParser');
const bcrypt = require('bcrypt');
const cors = require('cors');

app.use(express.static(path.join(__dirname, '/build')));
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());
app.use(cors());

const withDB = async (operations, res) => {
    try {
        await operations(db);
    } catch (err) {
        res.status(500).json({message: "Internal Server Error. Please try again later.", error: err});
    }
}

app.post('/api/users/register/:opnumber/:pin', async (req, res) => {
    withDB(async (db) => {
        console.log('add new user to collection:');

        const opnumber = req.params.opnumber;
        const pin = req.params.pin;
        const salt = bcrypt.genSaltSync(10);

        bcrypt.hash(pin, salt).then(async function (hashed) {
            console.log("done");
            // both insertOne and updateOne returns promise
            const result = await db.collection('users').insertOne({opnumber: opnumber, pin: hashed});
            const ID = result.insertedId;
                    // send a new token
            const payload = { opnumber: opnumber }; // TODO
            const token = JWT.sign(payload, SYSTEMCONFIG.PWDHASH, {
                    expiresIn: '1d'
                    
            });
            res.cookie('token', token, { httpOnly: true });
            res.json({statusText: 'Successfully created a new User!'});
            console.log("done");
        }).catch(() => console.log('error'));
    }, res);
});

app.post('/api/users/login/:opnumber/:pin', (req, res, next) => {
    withDB(async (db) => {
        const opnumber = req.params.opnumber;
        const pin = req.params.pin;
        console.log("entered");
        // findOne returns a promise
        db.collection('users').findOne({opnumber: opnumber}).then(function (result) {
            if (result) {
                let pinInDB = result.pin;
                bcrypt.compare(pin, pinInDB, function (err, same) {
                    if (err) {
                        res.status(500)
                          .json({
                              message: 'Internal Server Error.',
                              //error: 'Internal error please try again, ' + err.toString()
                        });
                        console.log("message1");
                      } else if (!same) { // password didnt match
                        res.status(401).json({
                            message: 'Unauthorized Access',
                            //error: 'Incorrect Password, please try again.'
                        });
                        console.log("message2");
                      } else { // password match, issue a token
                          const payload = { opnumber };
                          const token = JWT.sign(payload, SYSTEMCONFIG.PWDHASH, {
                              expiresIn: '1d'
                          });
                          res.cookie('token', token, { httpOnly: true }); //https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
                          // remove password and _id from response
                          let copy = JSON.parse(JSON.stringify(result));
                          copy.pin = null;
                          copy.opnumber = null;
                          res.status(200).json({message: 'success'});
                      }
                      console.log("message3");
                });
            } else { // didnt find user with given email
                res.status(401)
                .json({
                    message: 'Invalid Login',
                    error: 'We could not find you in our system.'
                }); 
                console.log("message4");   
            }
        }).catch(next); // this will be userID later
        
    }, res)
  });

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname + '/build/index.html'));
})

let db, client;

MongoClient.connect('mongodb://localhost:27017/', {useNewUrlParser: true, useUnifiedTopology: true}, function (err, mongoClient) {
    if (mongoClient) {
        client = mongoClient;
        db = client.db('my-blog');
        app.listen(8088, () => console.log('listening on port 8088'));
    }
});

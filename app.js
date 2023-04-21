//jshint esversion:6

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const express = require("express");
require("dotenv").config();
const bodyParser = require("body-parser")
const mongoose = require("mongoose")

const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const app = express()
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
})) 

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(`mongodb+srv://goodnewsadewole9:${process.env.MONGO}@cluster0.vcic5pk.mongodb.net/secretsDB?retryWrites=true&w=majority`)

app.use(express.static('public'))
app.use(bodyParser.urlencoded({ extended: false }))
app.set("view engine", "ejs")



const SecretsSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    facebookId:String,
    secret:String
})
SecretsSchema.plugin(passportLocalMongoose)
SecretsSchema.plugin(findOrCreate)

const Secret = mongoose.model('Secret', SecretsSchema);
passport.use(Secret.createStrategy());

passport.serializeUser(function(user, done) {
   done(null, user.id)
  });
  
  passport.deserializeUser(async function(id, done) {
    let err
    try{
        user = await Secret.findById(id)
        
    } catch(e){
        console.log(e)
        err=e
    }
    done(err, user)
  });
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
   Secret.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    Secret.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req,res){
    res.render("home")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
  
  );
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
});

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});


app.get("/login", function(req,res){
    res.render("login")
})

app.get("/register", function(req,res){
    res.render("register")
})
app.get("/secrets", async function(req, res){
    let aunthenticated 
    if(req.isAuthenticated()){
        aunthenticated = true
    }else{
        aunthenticated = false
    }
    try{
        const foundUsers = await Secret.find({secret:{$ne:null}})
        if(foundUsers){
        
            res.render("secrets", {UsersSubmittedSecret:foundUsers, aunthenticated:aunthenticated, user:req.user} )
        }
    }catch(e){
        console.log("Errorsss")
        console.log(e)
    }
    
})
    
app.post("/register", function(req,res){
   Secret.register({username:req.body.username}, req.body.password, function(err, user){
    if(err){
        console.log(err)
        res.redirect("/register")
    }else{
       passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets")
       })
    }
   })
})



app.post("/login", async function(req,res){
    const secret = new Secret({
        username: req.body.username,
        password: req.body.password
    })
    req.login(secret, function(err){
        if(err){
            console.log(err)
           
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets")
            })
        }
    })
})

app.get("/submit", function(req, res){
    if(req.isAuthenticated){
        res.render("submit")
    }else{
        res.redirect("/login")
    }
})
app.post("/submit", async function(req, res){
    const submittedSecret = req.body.secret
    try{
        const user = await Secret.findById(req.user.id)
        user.secret = submittedSecret
        try{
            await user.save()
            res.redirect("/secrets")
        }catch(e){
            console.log(e)
        }
    }catch(e){
        console.log("this error")
        console.log(e)
    }
})

app.get("/logout", function(req, res, next){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
  });
app.listen(process.env.PORT || "3000", function(){console.log("listening to port 3000")})



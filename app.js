//jshint esversion:6
require("dotenv").config();
// const md5=require("md5");
//const bcrypt=require("bcrypt");
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate=require("mongoose-findorcreate");
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app=express();
//const encrypt=require("mongoose-encryption");
app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({
  extended:true
}));

app.use(session({
  secret:"Our little secret.",
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DATABASE,{useNewUrlParser:true,useUnifiedTopology:true})
.then(() => console.log('DB connection successful!'));
mongoose.set("userCreateIndex",true);

const userSchema=new mongoose.Schema({
  //username:String,
  name:String,
  photo:String,
  googleId:String,
  facebookId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields: ['password']});
const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id,name:profile.displayName,photo:profile._json.picture }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields : ['id', 'photos', 'name', 'displayName', 'gender', 'profileUrl', 'email']
  },
  function(accessToken, refreshToken, profile, done) {
        //check user table for anyone with a facebook ID of profile.id
        User.findOne({
            facebookId: profile.id
        }, function(err, user) {
            if (err) {
                return done(err);
            }
            //No user was found... so create a new user with values from Facebook (all the profile. stuff)
            if (!user) {
                user = new User({
                    facebookId:profile.id,
                    name: profile.displayName,
                    photo:profile.photos[0].value
                });
                user.save(function(err) {
                    if (err) console.log(err);
                    return done(err, user);
                });
            } else {
                //found user. Return
                return done(err, user);
            }
        });
    }
));


app.get("/",function(req,res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/submit');
  });

  app.get('/auth/facebook',
    passport.authenticate('facebook'));

  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/submit');
    });

app.get("/login",function(req,res){
  res.render("login",{message:""});
});

app.get("/register",function(req,res){
  res.render("register",{otp:0,message:""});
});

app.get("/secrets",function(req,res){

  User.find({secret:{$ne:null}},function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        const color=['primary','secondary','success','danger','warning','info','dark'];
        res.render("secrets",{userswithsecrets:foundUser,color:color});
      }
    }
  });
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});
var u="username";
var n="name";
var p="password";
var otp=1234;

app.post("/verify",function(req,res){
  if(otp===req.body.otp){
    User.register({username:u,name:n,photo:"/img/default.png"},p,function(err,user){
      if(err){
        console.log(err);
      }else{
        res.render("login",{message:"account created please log in"});
      }
    });
  }else{
    console.log("bad otp");
    res.render("register",{otp:1,message:"Wrong OTP entered!"});
  }
});

app.post("/register",function(req,res){
  User.findOne({username:req.body.username},function(err,found){
    if(!found){
      otp=(Math.floor(Math.random()*10000)).toString();
        console.log(otp);
            const msg = {
          to: req.body.username,
          from: 'secret@funproject.com',
          subject: 'OTP verification',
          text: otp,
          html: '<strong>Your otp is '+otp+'</strong>',
          };
          sgMail.send(msg);
          u=req.body.username;
          n=req.body.name;
          p=req.body.password;
          res.render("register",{otp:1,message:""});
    }
    else{
      console.log("User already exists");
      res.render("register",{otp:0,message:"User already exists!"});
    }
  });
});


app.post("/login",function(req,res){

  const user=new User({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local",{ failureRedirect: '/error' })(req,res,function(){
        res.redirect("submit");
      });
    }
  });
});
app.get("/error",function(req,res){
  res.render("login",{message:"wrong email or password"});
});

app.get("/submit",function(req,res){
  // console.log(req.user);
   //const username=
  if(req.isAuthenticated()){
      User.findById(req.user.id,function(err,foundUser){
        const name=foundUser.name;
        const secret=foundUser.secret;
        const photo=foundUser.photo;
        res.render("submit",{name:name,my_secret:secret,photo:photo});
      });
  }else{
    res.redirect("/login");
  }
});


app.post("/submit",function(req,res){
  const secretSubmitted=req.body.secret;
  //console.log(req);
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret=secretSubmitted;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/delete",function(req,res){
  console.log(req.user.id);
  User.findOneAndDelete({_id:req.user.id},function(err){
    if(err){
      console.log(err);
    }else{
    res.redirect("/");
    }
  });
});

app.get("/deleteSecret",function(req,res){
  User.findByIdAndUpdate(req.user.id,{secret:""},function(err,user){});
  res.redirect("submit");
});

app.get("/contact",function(req,res){
  res.render("contact");
});

app.listen(3000,function(){
  console.log("sever started on port 3000");
});

require('dotenv').config();
const express = require("express") ;
const bodyParser = require("body-parser") ;
const ejs = require("ejs") ;
const mongoose = require("mongoose") ;
const session = require("express-session")
const passport = require("passport") ;
const passportLocalMongoose = require("passport-local-mongoose") ;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate") ;

const app = express() ;

app.use(express.static("public")) ;
app.set('view engine','ejs') ;
app.use(bodyParser.urlencoded({extrended:true})) ;

app.use(session({
  secret: "Our little secret.",
  resave:false,
  saveUninitialized:false,
}));
// built in function to initialise passport.
app.use(passport.initialize());
// this command tells the server to use passport to handle all our sessions.
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true}) ;
mongoose.set("useCreateIndex",true) ;

const userSchema = new mongoose.Schema({
  // not just a simple mongoose schema .using the mongoose schema class.
  email:String,
  password:String,
  googleId:String,
  secret:String
});

 //cool so basically this is what we will use to salt
// and hash user passwords and save them in our mongo db database.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate) ;

                 //defining the fields that we want to encrypt.
                 //process.env."environment_variable_name". to access its value fromm the .env file.

// after this we only need to to encrypt the fields we specified.
// the plugin will automatically encrypt passwords when we save them and automatically decrypt them when we find them.

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Oauth is basically a open standard for token based authorization .

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // access token is what gives us access to the customer data.
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home") ;
});



app.get("/auth/google",
  // initiating authentication with the strategy->google.
  passport.authenticate("google",{scope:["profile"]})
);
// this is the page that google will redirect the user too after successfull authentication.
app.get("/auth/google/secret",
   // then we locally authenticate the user.
  passport.authenticate("google", { failureRedirect: "/register" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });





app.get("/login",function(req,res){
  res.render("login") ;
});
app.get("/register",function(req,res){
  res.render("register") ;
});

app.get("/secrets",function(req,res){
      // finding users in which the secret field is not null.
      User.find({"secret":{$ne:null}},function(err,foundUsers){
        if(err){
          console.log(err);
        }else{
          if(foundUsers){
            // rendering the secrets.ejs page and passing the foudusers to it to display em.
            res.render("secrets",{usersWithSecrets:foundUsers}) ;
          }
        }
      });
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit") ;
  }else{
    res.redirect("/login") ;
  }
});

app.post("/submit",function(req,res){
  const submitted_secret = req.body.secret;
  // wheenever we start a log in session , passport saves the login details
  // and it can be tapped into using req.user
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submitted_secret ;
        foundUser.save(function(){
          res.redirect("/secrets") ;
        });
      }
    }
  });
});

app.get("/logout",function(req,res){
  // ends the session.
  req.logout() ;
  res.redirect("/") ;
});


app.post("/register",function(req,res){

     User.register({username:req.body.username},req.body.password,function(err,user){
       if(err){
         console.log(err);
         res.redirect("/register") ;
       }else{
         /* when we authenticate a user , we send a cookie to the
          browser telling it to store the session info and keeo this user logged in
          untill the browser is closed.*/
         passport.authenticate("local")(req,res,function(){
           // this callback will only be triggered if the authentication was successfull.
           res.redirect("/secrets") ;
         });
       }
     });
});

app.post("/login",function(req,res){
  const user = new User({
    username:req.body.username,
    password:req.body.password
  });
  // using the inbuilt login method of passport , which establishes a login session
  // establishing the fact that a user with the given password and username exists in our database.
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      // basically the user is authorized to view all the pages that he needs to after this
      // like the secrets page requires authentication , therefore the user needs to be authenticated before getting redirected there.
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets") ;
      });
    }
  });
});

// we stay logged in even if we close the tab because of the session cookie that was created by session.
// that makes the computer remember the current logged in and authenticated user.

// altho everytime we restart the server , the cookie is deleted and we are no longer authenticated.

app.listen("3000",function(){
  console.log("Server started on port 3000");
})

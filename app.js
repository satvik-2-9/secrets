require('dotenv').config();
const express = require("express") ;
const bodyParser = require("body-parser") ;
const ejs = require("ejs") ;
const mongoose = require("mongoose") ;
const session = require("express-session")
const passport = require("passport") ;
const passportLocalMongoose = require("passport-local-mongoose") ;


const app = express() ;

app.use(express.static("public")) ;
app.set('view engine','ejs') ;
app.use(bodyParser.urlencoded({extrended:true})) ;

app.use(session({
  secret: "Our little secret.",
  resave:false,
  saveUninitialized:false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true}) ;
mongoose.set("useCreateIndex",true) ;

const userSchema = new mongoose.Schema({
  // not just a simple mongoose schema .using the mongoose schema class.
  email:String,
  password:String
});

 //cool so basically this is what we will use to salt
// and hash user passwords and save them in our mongo db database.
userSchema.plugin(passportLocalMongoose);

                 //defining the fields that we want to encrypt.
                 //process.env."environment_variable_name". to access its value fromm the .env file.

// after this we only need to to encrypt the fields we specified.
// the plugin will automatically encrypt passwords when we save them and automatically decrypt them when we find them.

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/",function(req,res){
  res.render("home") ;
});
app.get("/login",function(req,res){
  res.render("login") ;
});
app.get("/register",function(req,res){
  res.render("register") ;
});

app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    res.render("secrets") ;
  }else{
    res.redirect("/login") ;
  }
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

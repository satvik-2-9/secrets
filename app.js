require('dotenv').config();
const express = require("express") ;
const bodyParser = require("body-parser") ;
const ejs = require("ejs") ;
const mongoose = require("mongoose") ;
const bcrypt= require("bcrypt") ;
const saltRounds=10 ;

const app = express() ;

app.use(express.static("public")) ;
app.set('view engine','ejs') ;
app.use(bodyParser.urlencoded({extrended:true})) ;

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true}) ;

const userSchema = new mongoose.Schema({
  // not just a simple mongoose schema .using the mongoose schema class.
  email:String,
  password:String
});


                 //defining the fields that we want to encrypt.
                 //process.env."environment_variable_name". to access its value fromm the .env file.

// after this we only need to to encrypt the fields we specified.
// the plugin will automatically encrypt passwords when we save them and automatically decrypt them when we find them.

const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res){
  res.render("home") ;
});
app.get("/login",function(req,res){
  res.render("login") ;
});
app.get("/register",function(req,res){
  res.render("register") ;
});

app.post("/register",function(req,res){

      // creating the hash along with 10 rounds of salting.
     bcrypt.hash(req.body.password,saltRounds,function(err,hash){
       const newUser = new User({
         email:req.body.username,
         password:hash
       });
       newUser.save(function(err){
         if(err){
           console.log(err);
         }else{
           res.render("secrets") ;
         }
       });
     });
});

app.post("/login",function(req,res){

    const username = req.body.username ;
    const password = req.body.password ;

    User.findOne({email:username},function(err,foundUser){
      if(err){
        console.log(err);
      }else{
        if(foundUser){
          bcrypt.compare(password,foundUser.password,function(err,results){
             if(results===true){
               res.render("secrets") ;
             }
          });
        }
      }
    });
});

app.listen("3000",function(){
  console.log("Server started on port 3000");
})

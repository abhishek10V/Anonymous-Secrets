const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const { default: mongoose } = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require("mongoose-findorcreate");

const bcrypt = require("bcrypt");
const saltrounds = 10;


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(express.static("public"));

app.use(session({
  secret : "This is my Secret.",
  resave : false,
  saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/UnnamedSecretsDB" , {useNewUrlParser : true});

const UserSchema = new mongoose.Schema({
  UserName : String,
  Email : String,
  Create_Password : String,
  Confirm_Password : String,
  Security_Question : String,
  Security_Answer : String
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const User = new mongoose.model("User" , UserSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
  done(null,user.id);
});
passport.deserializeUser(function(id,done){
  User.findById(id).then((user)=>{
      done(null, user);
  });

});


// passport.use(new GoogleStrategy({
//   clientID:     process.env.CLIENT_ID,
//   clientSecret: process.env.CLIENT_SECRET,
//   callbackURL: "http://localhost:3000/auth/google/secrets",
//   userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
// },
// function(request, accessToken, refreshToken, profile, done) {
//   console.log(profile);
//   User.findOrCreate({ googleId: profile.id }, function (err, user) {
//     return done(err, user);
//   });
// }
// ));

app.get("/" , function(req , res){
    res.render("home");
});

app.get("/register" , function(req , res){
  res.render("register");
});

app.get("/login" , function(req , res){
  res.render("login");
});

app.get("/reset_password" , function(req , res){
  res.render("reset_password");
});

app.get("/secrets" , function(req , res){
  if(req.isAuthenticated){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
});

app.get("/submit" , function(req , res){
  res.render("submit");
});


app.get("/auth/google" ,
  passport.authenticate("google" , {scope : ["profile"]})
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

app.post("/register" , function(req , res){
  const username = req.body.profileName;
  const email = req.body.email;
   const cr_password = req.body.create_password;
   const cnf_password= req.body.confirm_password;
  const sec_ques = req.body.Questions;
  const sec_ans = req.body.Answer;

  if(cr_password===cnf_password)
  {

    bcrypt.hash(cr_password, saltrounds, function(err, hash){
       const user = new User({
          UserName : username,
          Email : email,
          Create_Password : hash,
          Security_Question : sec_ques,
          Security_Answer : sec_ans
       });
  
      user.save().then(() => res.redirect("/secrets"));

    })
   
    // User.register({username : req.body.profileName} , req.body.create_password , function(err , user){
    //   if(err){
    //     console.log(err);
    //     res.redirect("/register");
    //   } else{
    //     passport.authenticate("local")(req , res , function(){
    //       res.redirect("/secrets");
    //     })
    //   }
    // })
  }
  else
  {
    res.send("<h1>Password does not Match , Please try again !!!</h1>")
  }

});

app.post("/login" , function(req , res){

  const username = req.body.username;
  const password = req.body.password;
  
  console.log(password);
  
  User.findOne({UserName : username}).then(function(foundUser){
  if(foundUser){
  
    console.log(foundUser.Create_Password);
  
    bcrypt.compare(password , foundUser.Create_Password ,function(err , result){
      
        if(result === true){
          res.render("secrets");
        }  else{
           res.send("<h1>Incorrect Password</h1>");
         }
   });
    } else{
    res.send("<h1>User not found</h1>");
  }
    
  });
});

app.post("/reset_password" , function(req , res){
  const username = req.body.username; 
  const email = req.body.email;
  const password = req.body.new_password;
  const confmPass = req.body.confirm_password;
  const confirmAnswer = req.body.Answer;

  User.findOne({Email : email}).then(function(foundUser){
    if(foundUser){
       if(foundUser.Security_Answer === confirmAnswer && foundUser.UserName === username){
        if(password === confmPass){
         
            bcrypt.hash(password , saltrounds, function(err, hash){
              if(err){
                console.log(err);
                res.redirect("/");
              } else{
             User.updateOne({Create_Password : foundUser.Create_Password} , {Create_Password : hash}).then(() => res.redirect("/login"));
              }
              
            });
        } else {
          res.send("<h1>Password do not Match , Please try again!!!</h1>")
        }
      
      } else {
        res.send("<h1>Username or Security Answer is not Correct, Please try Again</h1>");
       }
      } else{
      res.send("<h1>User not found</h1>");
    }
      
  });
});


app.listen(3000, function() {
    console.log("Server started on port 3000");
  })
var express = require('express');
var router = express.Router();
var User = require('../models/user');
//Declare JSON Web Token
var jwt = require('jsonwebtoken');


router.post('/register',  function(req,res,next){
  var user = new User({
    email: req.body.email,
    username: req.body.username,
    password: User.hashPassword(req.body.password),
    creation_dt: Date.now()
  });

  let promise = user.save();

  promise.then(function(doc){
    return res.status(201).json(doc);
  })

  promise.catch(function(err){
    return res.status(501).json({message: 'Error registering user.'})
  })
})




//Backend logic for the login page
router.post('/login', function(req,res,next){
  let promise = User.findOne({email:req.body.email}).exec();

  //Gets back the document
  promise.then(function(doc){
    if(doc){
      //Using the built in function from mongo isValid to check for token vadility
      if(doc.isValid(req.body.password)){
        
        //generates token. 1st param is payload, 2nd is the 'secret' algorithm to use for encription
        let token = jwt.sign({username:doc.username},'secret',{expiresIn:'1h'});
        
        //Returns the token back
        return res.status(200).json(token);
      }
      else{
        return res.status(501).json({message:'username or pass is incorrect'});
      }
    }else {
      return res.status(501).json({message: 'Cannot find email.'});
    }
  });

  //Error handling
  promise.catch(function(err){
    return res.status(501).json({message:'some internal error'});
  })
})
var decodedToken= '';
//here we are using the decoded token from the logic below
router.get('/username', function(req,res,next){
  return res.status(200).json(decodedToken.username);
})



var decodedToken= '';

//Logic for verifying the jwt token
function verifyToken(req,res,next){
  let token = req.query.token;
  
  //use the Jwt built in fn to verify
  jwt.verify(token,'secret', function(err, tokendata){
    //error handling
    if(err){
      return res.status(400).json({message:'Unauthorized request'});
    }
    //set the decoded token to tokendata
    if(tokendata){
      decodedToken = tokendata;
      next();
    }
  })
}

module.exports = router;

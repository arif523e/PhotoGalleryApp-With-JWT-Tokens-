//
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt');

//Declare database schema
var schema = new Schema({
    email : {type:String, require:true},
    username : {type:String, require:true},
    password : {type:String, require:true},
    creation_dt : {type:Date, require:true}
})

//bcrypt logic for hashing/salting passwords
schema.statics.hashPassword = function hashPassword(password){
    return bcrypt.hashSync(password,10);
}

schema.methods.isValid = function(hashedpassword){
    return  bcrypt.compareSync(hashedpassword, this.password);
}

module.exports = mongoose.model('User',schema);
const fs = require('fs');
let ZMXY = require('./index.js');
let zmxy = new ZMXY({
    appId: '',   //芝麻应用App ID
    appPrivateKey: fs.readFileSync(`${__dirname}/cert/app_private_key.pem`),  //App私钥
    zmxyPublicKey: fs.readFileSync(`${__dirname}/cert/zmxy_public_key.pem`)   //芝麻公钥
});

zmxy.verifyIvs({
    name: '',
    cert_no: ''
}).then(function(data){
    console.log(data);
}).catch(function(error){
    console.log(error);
});

const express = require('express');
const router = express.Router();
const http = require('http');
const jwt = require("jwt-simple");
const request = require('request-promise');
const async = require('async');
const config = require('../config/config');
const auth = require("../config/authForJwt.js")();
const passwordHash = require('password-hash');

router.post('/login', (req, res, next) => {
  async.waterfall([
    (callback) => {
      request.post({
        url: config.apiServer.url+'/users',
        form: {token:req.body.email,secret:req.body.password, type:"LOGIN_ID"}},
        (err, httpResponse, body) => {
          if(httpResponse.statusCode != 200){
            callback(httpResponse.statusCode, JSON.parse(body));
            return;
          }
          callback(null, JSON.parse(body));
        })
    },
    (result, callback) => {
      if (result) {
        callback(null, auth.payload(result.id));
      }
    }
  ],(error, callback) => {
      res.status(error == null ? 200 : error);
      res.json(callback);
  });
});

router.post('/sign-in', (req, res, next) => {
  async.waterfall([
    (callback) => {
      request.get({url: config.apiServer.url+'/users/login-id/'+req.body.email},
        (err, httpResponse, body) => {
          if(httpResponse.statusCode != 200){
            callback(httpResponse.statusCode, JSON.parse(body));
            return;
          }
          callback(null, JSON.parse(body));
        })
    },
    (result, callback) => {
      if (result) {
        if(result.length == 1){
          let userSso = result[0];
          if(passwordHash.verify(req.body.password,userSso.secret)){

            callback(null, auth.payload(result.id));
            return;
          }
          callback(401, {message: '로그인 정보를 찾을 수 없습니다.'});

        }
      }
    }
  ],(error, callback) => {
    res.status(error == null ? 200 : error);
    res.json(callback);
  });
});

module.exports = router;

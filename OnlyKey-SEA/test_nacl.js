define(function(require, exports, module) {

  module.exports = {
    start: function(testType) {
      var key1Name = "ALICE";
      var key2Name = "BOB";

      //  "hex" or "base64",  default is raw(Uint8Array)
      var encoding = "hex";

      ////-----------------------
      
      /* global */
      // var atob = require("atob");
      // var btoa = require("btoa");

      var forge = require('forge');
      var nacl = require('nacl');

      var encode;
      var decode;

      switch (encoding) {
        case "base64":
          encode = bytes_2_b64;
          decode = b64_2_bytes;
          break;
        case "hex":
          encode = toHexString;
          decode = toByteArray;
          break;
        default:
          encode = function(v) { return v; };
          decode = function(v) { return v; };
          break;
      }

      run();

      function run() {
        
        var sha256 = function(s) {
          var md = forge.md.sha256.create();
          md.update((function string2bytes() {
            var len = s.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
            return bytes;
          })());
          return Uint8Array.from(md.digest().toHex().match(/.{2}/g).map(function hexStrToDec(hexStr) {
            return ~~(new Number('0x' + hexStr).toString(10));
          }));
        };


        // var hash = function(s) { return ec.hash().update(s).digest() };

        var genKey = function(s) { 
          var h = sha256(s)
          return nacl.box.keyPair.fromSecretKey(h);
        };

        function dervivePublic(data) {
          // console.log("private-", data, encode(genKey(data).secretKey));
          // console.log("public-",  data, encode(genKey(data).publicKey));
          return encode(genKey(data).publicKey);
        }

        function derviveShared(data, sharePub) {
          // var x = nacl.box.before(decode(sharePub), genKey(data).secretKey);
          
          var x = nacl.scalarMult(genKey(data).secretKey, decode(sharePub));
          
          return encode(x);
        }

        var key1 = dervivePublic(key1Name);
        var key2 = dervivePublic(key2Name);

        var derive1 = derviveShared(key1Name, key2);
        var derive2 = derviveShared(key2Name, key1);


        console.log("key1Name",key1Name,key1);
        console.log("key2Name",key2Name,key2);
        console.log("derive1 ("+key1Name+") -> ("+ key2Name +")",derive1);
        console.log("derive2 ("+key2Name+") -> ("+ key1Name +")",derive2);
      }




      function bytes2string(bytes) {
        var ret = Array.from(bytes).map(function chr(c) {
          return String.fromCharCode(c);
        }).join('');
        return ret;
      }

      function string2bytes(s) {
        var len = s.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
        return bytes;
      }

      function u2f_b64(s) {
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      }

      function u2f_unb64(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        return atob(s + '==='.slice((s.length + 3) % 4));
      }

      function bytes_2_b64(bytes) {
        return u2f_b64(bytes2string(bytes));
      }


      function b64_2_bytes(b64) {
        return string2bytes(u2f_unb64(b64));
      }


      function toHexString(byteArray) {
        return Array.prototype.map.call(byteArray, function(byte) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
      }

      function toByteArray(hexString) {
        var result = [];
        for (var i = 0; i < hexString.length; i += 2) {
          result.push(parseInt(hexString.substr(i, 2), 16));
        }
        return Uint8Array.from(result);
      }
    }
  }
});
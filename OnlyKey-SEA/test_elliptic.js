define(function(require, exports, module) {

  module.exports = {
    start: function(testType) {
      var key1Name = "test13";
      var key2Name = "test22";

      //  "hex" or "base64",  default is raw(Uint8Array)
      var encoding = "hex";

      ////-----------------------

      // var atob = require("atob");
      // var btoa = require("btoa");

      var elliptic = require('../libs/elliptic');

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

      run('secp256k1');
      // run('p192');
      // run('p224');
      run('p256');
      // run('p384');
      // run('p521');
      run('curve25519');
      // run('ed25519');


      function run(keyType) {
        console.log(keyType);
        var ec = new elliptic.ec(keyType);


        var hash = function(s) { return ec.hash().update(s).digest() };

        var genKey = function(s) { return ec.keyFromPrivate(hash(s), "hex") };

        function dervivePublic(data) {
          console.log("private",genKey(data).getPrivate("hex"))
          console.log("public",genKey(data).getPublic(false, "hex"))
          return encode(genKey(data).getPublic().encode());
        }

        function derviveShared(data, sharePub) {
          return encode(genKey(data).derive(ec.keyFromPublic(decode(sharePub)).getPublic()).toArray());
        }

        var key1 = dervivePublic(key1Name);
        var key2 = dervivePublic(key2Name);

        var derive1 = derviveShared(key1Name, key2);
        var derive2 = derviveShared(key2Name, key1);


        console.log(key1);
        console.log(key2);
        console.log(derive1);
        console.log(derive2);
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
        return result;
      }
    }
  }
});
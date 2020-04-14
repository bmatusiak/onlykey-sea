define(function(require, exports, module) {
    
    console.log("onlykeyIndex");
    var onlykey = require("./onlykey-api.js");
    
    var pageLayout = $(require("text!./pageLayout.html"));
    
    pageLayout.find("#connect_onlykey").click(function(){
        onlykey.connect(function(){
            console.log("onlykey has connected");
            pageLayout.find("#connect_onlykey").hide();
            pageLayout.find("#connected_onlykey").show();
            
            pageLayout.find("#derive_public_key").click();
        },function(status){
            pageLayout.find("#connection_status").text(status)
        });
    });
    
    
    pageLayout.find("#derive_public_key").click(function(){
        onlykey.derive_public_key(async function(err,key,keyString){
            
            pageLayout.find("#onlykey_pubkey").val(key.join(""))
            
            $("#encryptKey").val("33333333333333333333333333333333")
            $("#decryptKey").val("33333333333333333333333333333333")
            
            
            pageLayout.find("#encryptData").val("test");
            $("#encryptBTN").click();
        });
    });
    
    
    pageLayout.find("#connect_onlykey").click();
    
    
    $("#main-container").html(pageLayout);
    
    $("#encryptBTN").click(async function(){
        
        var encData = pageLayout.find("#encryptData").val()
        var encryptoToKey = pageLayout.find("#encryptKey").val().split("")
             //onlykey.b642bytes()
        
        onlykey.derive_shared_secret(encryptoToKey, async function(err,sharedSecret){ 
            
            var enc = await GUN.SEA.encrypt(encData, sharedSecret);
            
            //pageLayout.find("#encryptData").val(enc);
            pageLayout.find("#decryptData").val(enc);
            pageLayout.find("#pills-decrypt-tab").click();
        });

        
    });
    
    $("#decryptBTN").click(async function(){
        
        var decData = pageLayout.find("#decryptData").val()
        var decryptoToKey = onlykey.b642bytes(pageLayout.find("#decryptKey").val())
        
        onlykey.derive_shared_secret(decryptoToKey, async function(err,sharedSecret){ 
            
            //var enc = await SEA.encrypt('shared data', await SEA.secret(bob.epub, alice));

            var dec = await GUN.SEA.decrypt(decData, sharedSecret);
            
            pageLayout.find("#encryptData").val(dec);
            pageLayout.find("#pills-encrypt-tab").click();
        });

        
    });
    
})

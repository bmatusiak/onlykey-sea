define(function(require, exports, module) {

    console.log("onlykeyIndex");
    var onlykey = require("./onlykey-api.js");

    var pageLayout = $(require("text!./pageLayout.html"));

    pageLayout.find("#connect_onlykey").click(function() {
        onlykey.connect(function() {
            console.log("onlykey has connected");
            pageLayout.find("#connect_onlykey").hide();
            pageLayout.find("#connected_onlykey").show();

            pageLayout.find("#derive_public_key").click();
        }, function(status) {
            pageLayout.find("#connection_status").text(status)
        });
    });


    pageLayout.find("#derive_public_key").click(function() {
        onlykey.derive_public_key(async function(err, key, keyString) {

            pageLayout.find("#onlykey_pubkey").val(key)

            if ($("#encryptKey").val() == "")
                $("#encryptKey").val(key)

            if ($("#decryptKey").val() == "")
                $("#decryptKey").val(key)


            pageLayout.find("#encryptData").val("test");
            //$("#encryptBTN").click();

            (async function() {
                var sharedSecret = await SEA.secret({
                    epub: key
                }, JSON.parse($("#sea_test_key").val()))

                $("#sea_test_shared_secret").val(sharedSecret)


                onlykey.derive_shared_secret(JSON.parse($("#sea_test_key").val()).epub, async function(err, sharedSecret) {

                    $("#ok_test_shared_secret").val(sharedSecret)
                });

            })()

        });
    });


    pageLayout.find("#connect_onlykey").click();


    $("#main-container").html(pageLayout);

    $("#encryptBTN").click(async function() {

        var encData = pageLayout.find("#encryptData").val()
        var encryptoToKey = pageLayout.find("#encryptKey").val(); //.split("")
        //onlykey.b642bytes()

        onlykey.derive_shared_secret(encryptoToKey, async function(err, sharedSecret) {

            var enc = await GUN.SEA.encrypt(encData, sharedSecret);

            //pageLayout.find("#encryptData").val(enc);
            pageLayout.find("#decryptData").val(enc);
            //pageLayout.find("#pills-decrypt-tab").click();
        });


    });

    $("#decryptBTN").click(async function() {

        var decData = pageLayout.find("#decryptData").val()
        var decryptoToKey = pageLayout.find("#decryptKey").val()

        onlykey.derive_shared_secret(decryptoToKey, async function(err, sharedSecret) {

            //var enc = await SEA.encrypt('shared data', await SEA.secret(bob.epub, alice));

            var dec = await GUN.SEA.decrypt(decData, sharedSecret);

            pageLayout.find("#encryptData").val(dec);
            //pageLayout.find("#pills-encrypt-tab").click();
        });


    });

    // (async function() {
    //     $("#sea_test_key").text(JSON.stringify(await GUN.SEA.pair()))
    // })()

})

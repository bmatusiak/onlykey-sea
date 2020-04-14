var SEA = Gun.SEA;


var pageLayout = `
<br/><h1> Sea Encryption </h1>
<br/>
Encryption Key<br/>
<textarea id="myPair" style="width:100%;height:160px"></textarea>
<br/> Encrypted Key Password
<br/>
<input id="keyPW" type="password" style="width:100%;"></textarea>
My ePub<br/>
<input readonly="readonly" style="width:100%" id="myePub">
<br/>
<br/>
<button id="genpairs" class="btn btn-danger float-right">Generate New KeyPair</button>
<br class="clearfix">
<hr> Shared ePub
<br/>
<input id="shareEpub" style="width:100%;"></textarea>
<hr> Decrypted Data
<br/>
<textarea id="databoxIn" style="width:100%;height:150px"></textarea>
<br/>
<button id="encData">Encrypt</button>
<hr> Encrypted Data
<br/>
<textarea id="databoxOut" style="width:100%;height:150px"></textarea>
<br/>
<button id="decData">Decrypt</button>
<br/>
`


$("#main-container").html(pageLayout);
init();

function init() {
    var keyDecryptedWithPW = false;
    var myPair = false;

    $("#genpairs").click(function() {
        (async() => {
            if($("#keyPW").val().length){
                window.localStorage.pair = await SEA.encrypt(myPair = await SEA.pair(), $("#keyPW").val());
                keyDecryptedWithPW = true;
                initPair();
            }else{
                $("#myPair").val("");
                $("#myePub").val("Please Enter Key Password");
            }
        })();
    });

    $("#myPair").change(function() {
        (async() => {
            try{
                if($("#myPair").val().length && $("#keyPW").val().length)
                var testDEC = await SEA.decrypt( $("#myPair").val(), $("#keyPW").val());
                if(testDEC && testDEC.epub){
                    window.localStorage.pair = $("#myPair").val();
                    $("#keyPW").change();
                }
            }catch(e){}
        })();
        console.log($("#myPair").val())
    });


    $("#keyPW").change(function() {
        (async() => {
            if (keyDecryptedWithPW) {
                window.localStorage.pair = await SEA.encrypt(myPair, $("#keyPW").val());
            } else {
                myPair = await SEA.decrypt(window.localStorage.pair, $("#keyPW").val());
                initPair();
            }
        })();

    });

    function initPair() {
        (async() => {
            if (!myPair && $("#keyPW").val().length) {
                myPair = await SEA.decrypt(window.localStorage.pair, $("#keyPW").val());
            }else if($("#keyPW").val().length == 0){
                $("#myPair").val(window.localStorage.pair);
                $("#myePub").val("Please Enter Key Password");
                
            }

            if (myPair) {
                $("#myPair").val(window.localStorage.pair)
                // $("#myPair").val(JSON.stringify(myPair)
                //     //.split(":").join(":\r\n")
                //     .split('",').join('",\r\n')
                //     .split('}').join('\r\n}')
                //     .split('{').join('{\r\n')
                // );
                $("#myePub").val(myPair.epub);
            }
        })();
    }

    initPair();

    $("#encData").click(function() {
        (async() => {
            var sharedEpub = $("#shareEpub").val();

            var thedata = $("#databoxIn").val()

            var sharedSecret;
            if (sharedEpub == "" || myPair.epub == sharedEpub) {
                sharedSecret = myPair
            } else {
                sharedSecret = await SEA.secret(sharedEpub, myPair)
            }

            var enc = await SEA.encrypt(thedata, sharedSecret);

            $("#databoxOut").text(enc)
            //await SEA.decrypt(enc, await SEA.secret(alice.epub, bob));

        })();
    })


    $("#decData").click(function() {
        (async() => {
            var sharedEpub = $("#shareEpub").val();

            var thedata = $("#databoxOut").val()

            var sharedSecret;
            if (sharedEpub == "" || myPair.epub == sharedEpub) {
                sharedSecret = myPair
            } else {
                sharedSecret = await SEA.secret(sharedEpub, myPair)
            }

            var dec = await SEA.decrypt(thedata, sharedSecret);

            $("#databoxIn").val(dec)
        })();
    })
}
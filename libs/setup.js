require.config({
    baseUrl: './',
    paths: {
        text:"libs/text",
        nacl: "libs/nacl.min",
        forge: "libs/forge.min",
        crypto: "libs/webcrypto-core",
    }
});

require(["./OnlyKey-SEA/index.js"], function() {});
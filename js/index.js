(function() {
    var phraseChangeTimeoutEvent
    var seedChangedTimeoutEvent
    var seed = null
    var networkSelectIndex

    var addressRowTemplate = $("#address-row-template");

    var generationProcesses = []

    var DOM = {}
    DOM.phrase = $("#mnemonic")
    DOM.seed = $(".seed");
    DOM.generate = $("#generate")
    DOM.purpose = $("#purpose")
    DOM.phraseNetwork = $("#network-phrase")
    DOM.network = $(".network")
    DOM.hardenedAddresses = $(".hardened-addresses")
    DOM.addresses = $(".addresses")
    DOM.csvTab = $("#csv-tab a")
    DOM.csv = $(".csv");
    DOM.rowsToAdd = $(".rows-to-add");
    DOM.more = $(".more");
    DOM.moreRowsStartIndex = $(".more-rows-start-index");

    DOM.feedback = $(".feedback");

    DOM.appName = $("#appname")
    DOM.appId = $("#appid")
    DOM.txId = $("#txid")


    function init() {
        DOM.phrase.on("input", onPhraseChanged);
        DOM.seed.on("input", delayedSeedChanged);
        DOM.generate.on('click', generate);
        DOM.network.on("change", networkChanged);
        DOM.hardenedAddresses.on("change", calcForDerivationPath);
        DOM.csvTab.on("click", updateCsv);
        DOM.more.on("click", showMore);
        populateNetworkSelect();
        hidePending();
    }

    function onPhraseChanged() {
        if (phraseChangeTimeoutEvent != null) {
            clearTimeout(phraseChangeTimeoutEvent);
        }
        phraseChangeTimeoutEvent = setTimeout(phraseChanged, 400);
    }

    function delayedSeedChanged() {
        // Warn if there is an existing mnemonic or passphrase.
        if (DOM.phrase.val().length > 0) {
            if (!confirm("This will clear existing mnemonic and passphrase")) {
                DOM.seed.val(seed);
                return
            }
        }
        hideValidationError();
        showPending();
        // Clear existing mnemonic and passphrase
        DOM.phrase.val("");
        clearAddressesList();
        seed = null;
        if (seedChangedTimeoutEvent != null) {
            clearTimeout(seedChangedTimeoutEvent);
        }
        seedChangedTimeoutEvent = setTimeout(seedChanged, 400);
    }

    function seedChanged() {
        showPending();
        hideValidationError();
        seed = DOM.seed.val()
        // Calculate and display
        calcForDerivationPath();
    }

    function networkChanged(e) {
        clearAddressesList();
        // DOM.litecoinLtubContainer.addClass("hidden");
        // DOM.bitcoinCashAddressTypeContainer.addClass("hidden");
        networkSelectIndex = e.target.value;
        var network = networks[networkSelectIndex];
        network.onSelect();
        // adjustNetworkForSegwit();
        // if (seed != null) {
        //     phraseChanged();
        // }
        // else {
        //     rootKeyChanged();
        // }
    }

    function clean() {
        document.getElementById("privkey").innerHTML = ''
        document.getElementById("pubkey").innerHTML = ''
        document.getElementById("addr").innerHTML = ''
    }

    function generate() {
        console.log("generate")
        var mnemonic = generateMnemonic()
        DOM.phrase.val(mnemonic)
        phraseChangeTimeoutEvent = setTimeout(phraseChanged, 400);
    }

    function phraseChanged() {
        console.log("phraseChanged")
        var value = DOM.phrase.val()
        if (value == "") return

        seed = getSeedFromMnemonic(value).toString('hex')
        calcForDerivationPath()
    }

    function generateAppID() {
        var privekey = DOM.privateKey.val()
        if (privekey == "") {
            alert("Please input mnemonic or private key!")
            return
        }

        var name = DOM.appName.val()
        var appId = sign(name, privekey)
        DOM.appId.val(appId)

        setInfoByPrivkey(accId, accSecret, "Dev/" + name + "/AppID", appId, privekey)
        .then(ret => {
            DOM.txId.val(ret.txid)
        })
    }

    function doverify() {
        var srcdata = $("#srcdata").val()
        if (srcdata == "") {
            alert("Please input source data!")
            return
        }

        var signed = $("#signeddata").val()
        if (signed == "") {
            alert("Please input signed data!")
            return
        }

        var pubkey = $("#verifypub").val()
        if (pubkey == "") {
            alert("Please input public key!")
            return
        }

        var ret = verify(srcdata, signed, pubkey)
        alert(ret)
    }

    function calcForDerivationPath() {
        clearAddressesList();
        showPending();

        displayBip32Info();
    }

    function clearAddressesList() {
        DOM.addresses.empty();
        DOM.csv.val("");
        stopGenerating();
    }

    function stopGenerating() {
        while (generationProcesses.length > 0) {
            var generation = generationProcesses.shift();
            generation.stop();
        }
    }

    function showPending() {
        DOM.feedback
            .text("Calculating...")
            .show();
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }

    function showValidationError(errorText) {
        DOM.feedback
            .text(errorText)
            .show();
    }

    function hideValidationError() {
        DOM.feedback
            .text("")
            .hide();
    }

    function updateCsv() {
        var tableCsv = "path,address,public key,private key\n";
        var rows = DOM.addresses.find("tr");
        for (var i=0; i<rows.length; i++) {
            var row = $(rows[i]);
            var cells = row.find("td");
            for (var j=0; j<cells.length; j++) {
                var cell = $(cells[j]);
                if (!cell.children().hasClass("invisible")) {
                    tableCsv = tableCsv + cell.text();
                }
                if (j != cells.length - 1) {
                    tableCsv = tableCsv + ",";
                }
            }
            tableCsv = tableCsv + "\n";
        }
        DOM.csv.val(tableCsv);
    }

    function displayAddresses(start, total) {
        generationProcesses.push(new (function() {

            var rows = [];

            this.stop = function() {
                for (var i=0; i<rows.length; i++) {
                    rows[i].shouldGenerate = false;
                }
                hidePending();
            }

            for (var i=0; i<total; i++) {
                var index = i + start;
                var isLast = i == total - 1;
                rows.push(new TableRow(index, isLast));
            }

        })());
    }

    function displayBip32Info() {
        // Display the key
        DOM.seed.val(seed);

        clearAddressesList();
        var initialAddressCount = parseInt(DOM.rowsToAdd.val());
        displayAddresses(0, initialAddressCount);
    }

    function showMore() {
        var rowsToAdd = parseInt(DOM.rowsToAdd.val());
        if (isNaN(rowsToAdd)) {
            rowsToAdd = 20;
            DOM.rowsToAdd.val("20");
        }
        var start = parseInt(DOM.moreRowsStartIndex.val())
        if (isNaN(start)) {
            start = lastIndexInTable() + 1;
        }
        else {
            var newStart = start + rowsToAdd;
            DOM.moreRowsStartIndex.val(newStart);
        }
        if (rowsToAdd > 200) {
            var msg = "Generating " + rowsToAdd + " rows could take a while. ";
            msg += "Do you want to continue?";
            if (!confirm(msg)) {
                return;
            }
        }
        showPending();
        displayAddresses(start, rowsToAdd);
    }

    function lastIndexInTable() {
        var pathText = DOM.addresses.find(".index").last().text();
        var pathBits = pathText.split("/");
        var lastBit = pathBits[pathBits.length-1];
        var lastBitClean = lastBit.replace("'", "");
        return parseInt(lastBitClean);
    }

    function networkIsELA() {
        return networks[DOM.network.val()].name == "ELA - Elastos"
    }

    function networkIsEthereum() {
        return networks[DOM.network.val()].name == "ETH - Ethereum"

    }

    function TableRow(index, isLast) {

        var self = this;
        this.shouldGenerate = true;
        var useHardenedAddresses = DOM.hardenedAddresses.prop("checked");

        function init() {
            calculateValues();
        }

        function calculateValues() {
            setTimeout(function() {
                if (!self.shouldGenerate) {
                    return;
                }
                // derive HDkey for this row of the table
                // var key = "NA";
                // if (useHardenedAddresses) {
                //     key = bip32ExtendedKey.deriveHardened(index);
                // }
                // else {
                //     key = bip32ExtendedKey.derive(index);
                // }
                // // bip38 requires uncompressed keys
                // // see https://github.com/iancoleman/bip39/issues/140#issuecomment-352164035
                // var keyPair = key.keyPair;
                // var useUncompressed = useBip38;
                // if (useUncompressed) {
                //     keyPair = new libs.bitcoin.ECPair(keyPair.d, null, { network: network, compressed: false });
                //     if(isGRS())
                //         keyPair = new libs.groestlcoinjs.ECPair(keyPair.d, null, { network: network, compressed: false });

                // }
                // // get address
                // var address = keyPair.getAddress().toString();
                // // get privkey
                // var hasPrivkey = !key.isNeutered();
                // var privkey = "NA";
                // if (hasPrivkey) {
                //     privkey = keyPair.toWIF();
                //     // BIP38 encode private key if required
                //     if (useBip38) {
                //         if(isGRS())
                //             privkey = libs.groestlcoinjsBip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function(p) {
                //                 console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
                //             }, null, networks[DOM.network.val()].name.includes("Testnet"));
                //         else
                //             privkey = libs.bip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function(p) {
                //                 console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
                //             });
                //     }
                // }
                // // get pubkey
                // var pubkey = keyPair.getPublicKeyBuffer().toString('hex');
                var indexText = getDerivationPath() + "/" + index;
                if (useHardenedAddresses) {
                    indexText = indexText + "'";
                }
                // // Ethereum values are different
                // if (networkIsEthereum()) {
                //     var pubkeyBuffer = keyPair.getPublicKeyBuffer();
                //     var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
                //     var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
                //     var hexAddress = addressBuffer.toString('hex');
                //     var checksumAddress = libs.ethUtil.toChecksumAddress(hexAddress);
                //     address = libs.ethUtil.addHexPrefix(checksumAddress);
                //     pubkey = libs.ethUtil.addHexPrefix(pubkey);
                //     if (hasPrivkey) {
                //         privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer());
                //     }
                // }

                if (networkIsELA()) {
                    let elaAddress = calcAddressForELA(seed, 0, 0, 0, index);
                    address = elaAddress.address;
                    privkey = elaAddress.privateKey;
                    pubkey = elaAddress.publicKey;
                    did = elaAddress.did;
                }

                addAddressToList(indexText, address, pubkey, privkey, did);
                if (isLast) {
                    hidePending();
                    updateCsv();
                }
            }, 50)
        }

        init();

    }


    function getDerivationPath() {
        return "m/44'/" + networks[networkSelectIndex].coinValue + "'/0'/0"
    }

    function addAddressToList(indexText, address, pubkey, privkey, did) {
        var row = $(addressRowTemplate.html());
        // Elements
        var indexCell = row.find(".index span");
        var addressCell = row.find(".address span");
        var pubkeyCell = row.find(".pubkey span");
        var privkeyCell = row.find(".privkey span");
        var didCell = row.find(".did span");
        // Content
        indexCell.text(indexText);
        addressCell.text(address);
        pubkeyCell.text(pubkey);
        privkeyCell.text(privkey);
        if (did != undefined) {
            didCell.text(did);
            didCell.removeClass("hidden")
        } else {
            didCell.addClass("hidden")
        }
        // Visibility
        DOM.addresses.append(row);
    }

    function calcAddressForELA(seed, coin, account, change, index) {
        if (!networkIsELA()) {
            return;
        }

        var publicKey = generateSubPublicKey(getMasterPublicKey(seed), change, index);
        return {
            privateKey: generateSubPrivateKey(seed, coin, account, change, index),
            publicKey: publicKey,
            address: getAddress(publicKey.toString('hex')),
            did: getDid(publicKey.toString('hex'))
        };
    }

    function setHdCoinPath() {
        DOM.purpose.val(getDerivationPath())
    }

    function populateNetworkSelect() {
        for (var i=0; i<networks.length; i++) {
            var network = networks[i];
            var option = $("<option>");
            option.attr("value", i);
            option.text(network.name);
            if (network.name == "ELA - Elastos") {
                option.prop("selected", true);
                networkSelectIndex = i;
                network.onSelect();
            }
            DOM.phraseNetwork.append(option);
        }
    }

    var networks = [
        {
            name: "BTC - Bitcoin",
            coinValue: 0,
            onSelect: function() {
                setHdCoinPath();
            },
        },
        {
            name: "ELA - Elastos",
            coinValue: 0,
            onSelect: function () {
                setHdCoinPath();
            },
        },
        {
            name: "ETH - Ethereum",
            coinValue: 60,
            onSelect: function() {
                setHdCoinPath();
            },
        }
    ]

    init();

})();

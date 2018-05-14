describe('Long running Encryption/Decryption', function () {
    for (let i=0; i< 100; i++) {
        it('Successful encrypt/decrypt completely random data ' + (i+1) + '/100', function (done) {
            let prm = Gpgmejs.init();
            let data = bigString(2);
                prm.then(function (context) {
                    context.encrypt(data,
                        inputvalues.encrypt.good.fingerprint).then(
                            function (answer){
                                expect(answer).to.not.be.empty;
                                expect(answer.data).to.be.a("string");
                                expect(answer.data).to.include(
                                    'BEGIN PGP MESSAGE');
                                expect(answer.data).to.include(
                                    'END PGP MESSAGE');
                                context.decrypt(answer.data).then(
                                    function(result){
                                        expect(result).to.not.be.empty;
                                        expect(result.data).to.be.a('string');
                                        expect(result.data).to.equal(data);
                                        context.connection.disconnect();
                                        done();
                                });
                        });
                });
        }).timeout(5000);
    };

    it('Successful encrypt 1 MB Uint8Array', function (done) {
        //TODO: this succeeds, but result may be bogus (String with byte values as numbers)
        let prm = Gpgmejs.init();
        let data = bigUint8(1);
        prm.then(function (context) {
                context.encrypt(data,
                    inputvalues.encrypt.good.fingerprint).then(
                        function (answer){
                            expect(answer).to.not.be.empty;
                            expect(answer.data).to.be.a("string");
                            expect(answer.data).to.include(
                                'BEGIN PGP MESSAGE');
                            expect(answer.data).to.include(
                                'END PGP MESSAGE');
                            context.decrypt(answer.data).then(
                                function(result){
                                    expect(result).to.not.be.empty;
                                    expect(result.data).to.be.a('string');
                                    expect(result.data).to.equal(data);
                                    done();
                            });
                    });
            });
    }).timeout(5000);

});

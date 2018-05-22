describe('Long running Encryption/Decryption', function () {
    for (let i=0; i < 100; i++) {
        it('Successful encrypt/decrypt completely random data ' + (i+1) + '/100', function (done) {
            let prm = Gpgmejs.init();
            let data = bigString(2*1024*1024);
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
                                        if (result.data.length !== data.length) {
                                            console.log('diff: ' + (result.data.length - data.length));
                                            for (let i=0; i < result.data.length; i++){
                                                if (result.data[i] !== data[i]){
                                                    console.log('position: ' + i);
                                                    console.log('result : '+ result.data.charCodeAt(i) + result.data[i-2] + result.data[i-1] + result.data[i] + result.data[i+1] + result.data[i+2]);
                                                    console.log('original: ' + data.charCodeAt(i) + data[i-2] + data[i-1] + data[i] + data[i+1] + data[i+2]);
                                                    break;
                                                }
                                            }
                                        }
                                        expect(result.data).to.equal(data);
                                        context.connection.disconnect();
                                        done();
                                });
                        });
                });
        }).timeout(8000);
    };

});

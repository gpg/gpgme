/**
* Testing nativeMessaging. This is a temporary plugin using the gpgmejs
  implemetation as contained in src/
*/
function buttonclicked(event){
    let data = document.getElementById("text0").value;
    let keyId = document.getElementById("key").value;
    let enc = Gpgmejs.encrypt(data, [keyId]).then(function(answer){
        console.log(answer);
        console.log(answer.type);
        console.log(answer.data);
        alert(answer.data);
    }, function(errormsg){
        alert('Error: '+ errormsg);
    });
};

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById("button0").addEventListener("click",
    buttonclicked);
  });

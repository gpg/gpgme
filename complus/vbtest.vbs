' Demo script to generate a RFC2015 compliant message using Gpgcom
Dim gpg, body, crlf

crlf = chr(10) & chr(13)

' Create out Gpgcom object
set gpg = CreateObject("Gpgcom.Gpgme")
' We must use the ASCII armor and switch to textmode
gpg.armor = true
gpg.textmode = true

' Set the secret message
gpg.plaintext = "This is the secret message."  'or: InputBox('Enter message:")

' Set the Recipient.  You may also use a keyID or an fingerprint
gpg.AddRecipient "alice"

' And encrypt the stuff
gpg.encrypt

' Build the MIME message
body = "Content-Type: multipart/encrypted; boundary=" 
body = body & Chr(34) & "=-=-=-=" & Chr(34) & crlf & "    protocol=" & Chr(34)
body = body & "application/pgp-encrypted" & Chr(34) & crlf & crlf
body = body & "--=-=-=-=" & crlf
body = body & "Content-Type: application/pgp-encrypted" & crlf & crlf
body = body & "Version: 1" & crlf & crlf
body = body & "--=-=-=-=" & crlf
body = body & "Content-Type: application/octet-stream" & crlf & crlf
body = body & gpg.ciphertext 
body = body & "--=-=-=-=--" & crlf 

' And display it
Print body

' output function for the windows scripting host
sub Print(x)
     WScript.Echo x
end sub

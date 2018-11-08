;;;; gpgme.lisp

;;; Copyright (C) 2006 g10 Code GmbH
;;;
;;; This file is part of GPGME-CL.
;;;
;;; GPGME-CL is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 2 of the License, or
;;; (at your option) any later version.
;;;
;;; GPGME-CL is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Lesser General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GPGME; if not, write to the Free Software Foundation,
;;; Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

;;; TODO

;;; Set up the library.

(in-package :gpgme)

(deftype byte-array ()
  '(simple-array (unsigned-byte 8) (*)))

(deftype character-array ()
  '(simple-array character (*)))

;;; Debugging.

(defvar *debug* nil "If debugging output should be given or not.")

;;; Load the foreign library.

(define-foreign-library libgpgme
  (:unix "libgpgme.so")
  (t (:default "libgpgme")))

(use-foreign-library libgpgme)

;;; System dependencies.

; Access to ERRNO.
(defcfun ("strerror" c-strerror) :string
  (err :int))

(defun get-errno ()
  *errno*)

(defun set-errno (errno)
  (setf *errno* errno))

(define-condition system-error (error)
  ((errno :initarg :errno :reader system-error-errno))
  (:report (lambda (c stream)
	     (format stream "System error: ~A: ~A"
		     (system-error-errno c)
		     (c-strerror (system-error-errno c)))))
  (:documentation "Signalled when an errno is encountered."))

; Needed to write passphrases.
(defcfun ("write" c-write) ssize-t
  (fd :int)
  (buffer :string) ; Actually :pointer, but we only need string.
  (size size-t))

(defun system-write (fd buffer size)
  (let ((res (c-write fd buffer size)))
    (when (< res 0) (error 'system-error :errno (get-errno)))
    res))

;;;
;;; C Interface Definitions
;;;

;;; Data Type Interface

;;; Some new data types used for easier translation.

;;; The number of include certs.  Translates to NIL for default.
(defctype cert-int-t
    (:wrapper :int
     :from-c translate-cert-int-t-from-foreign
     :to-c translate-cert-int-t-to-foreign))

;;; A string that may be NIL to indicate a null pointer.
(defctype string-or-nil-t
    (:wrapper :string
     :to-c translate-string-or-nil-t-to-foreign))

;;; Some opaque data types used by GPGME.

(defctype gpgme-ctx-t
    (:wrapper :pointer
     :to-c translate-gpgme-ctx-t-to-foreign)
  "The GPGME context type.")

(defctype gpgme-data-t
    (:wrapper :pointer
     :to-c translate-gpgme-data-t-to-foreign)
  "The GPGME data object type.")

;;; Wrappers for the libgpg-error library.

(defctype gpgme-error-t
    (:wrapper gpg-error::gpg-error-t
     :from-c translate-gpgme-error-t-from-foreign
     :to-c translate-gpgme-error-t-to-foreign)
  "The GPGME error type.")

(defctype gpgme-error-no-signal-t
    (:wrapper gpg-error::gpg-error-t
     :from-c translate-gpgme-error-no-signal-t-from-foreign)
  "The GPGME error type (this version does not signal conditions in translation.")

(defctype gpgme-err-code-t gpg-error::gpg-err-code-t
  "The GPGME error code type.")

(defctype gpgme-err-source-t gpg-error::gpg-err-source-t
  "The GPGME error source type.")

(defun gpgme-err-make (source code)
  "Construct an error value from an error code and source."
  (gpg-err-make source code))

(defun gpgme-error (code)
  "Construct an error value from an error code."
  (gpgme-err-make :gpg-err-source-gpgme code))

(defun gpgme-err-code (err)
  "Retrieve an error code from the error value ERR."
  (gpg-err-code err))

(defun gpgme-err-source (err)
  "Retrieve an error source from the error value ERR."
  (gpg-err-source err))

(defun gpgme-strerror (err)
  "Return a string containing a description of the error code."
  (gpg-strerror err))

(defun gpgme-strsource (err)
  "Return a string containing a description of the error source."
  (gpg-strsource err))

(defun gpgme-err-code-from-errno (err)
  "Retrieve the error code for the system error.  If the system error
   is not mapped, :gpg-err-unknown-errno is returned."
  (gpg-err-code-from-errno err))

(defun gpgme-err-code-to-errno (code)
  "Retrieve the system error for the error code.  If this is not a
   system error, 0 is returned."
  (gpg-err-code-to-errno code))

(defun gpgme-err-make-from-errno (source err)
  (gpg-err-make-from-errno source err))

(defun gpgme-error-from-errno (err)
  (gpg-error-from-errno err))

;;;

(defcenum gpgme-data-encoding-t
  "The possible encoding mode of gpgme-data-t objects."
  (:none 0)
  (:binary 1)
  (:base64 2)
  (:armor 3)
  (:url 4)
  (:urlesc 5)
  (:url0 6)
  (:mime 7))

;;;

(defcenum gpgme-pubkey-algo-t
  "Public key algorithms from libgcrypt."
  (:rsa 1)
  (:rsa-e 2)
  (:rsa-s 3)
  (:elg-e 16)
  (:dsa 17)
  (:ecc 18)
  (:elg 20)
  (:ecdsa 301)
  (:ecdh 302)
  (:eddsa 303))

(defcenum gpgme-hash-algo-t
  "Hash algorithms from libgcrypt."
  (:none 0)
  (:md5 1)
  (:sha1 2)
  (:rmd160 3)
  (:md2 5)
  (:tiger 6)
  (:haval 7)
  (:sha256 8)
  (:sha384 9)
  (:sha512 10)
  (:sha224 11)
  (:md4 301)
  (:crc32 302)
  (:crc32-rfc1510 303)
  (:crc24-rfc2440 304))

;;;

(defcenum gpgme-sig-mode-t
  "The available signature modes."
  (:none 0)
  (:detach 1)
  (:clear 2))

;;;

(defcenum gpgme-validity-t
  "The available validities for a trust item or key."
  (:unknown 0)
  (:undefined 1)
  (:never 2)
  (:marginal 3)
  (:full 4)
  (:ultimate 5))

;;;

(defcenum gpgme-protocol-t
  "The available protocols."
  (:openpgp 0)
  (:cms 1)
  (:gpgconf 2)
  (:assuan 3)
  (:g13 4)
  (:uiserver 5)
  (:spawn 6)
  (:default 254)
  (:unknown 255))

;;;

(defbitfield (gpgme-keylist-mode-t :unsigned-int)
  "The available keylist mode flags."
  (:local 1)
  (:extern 2)
  (:sigs 4)
  (:sig-notations)
  (:with-secret 16)
  (:with-tofu 32)
  (:ephemeral 128)
  (:validate 256))

;;;

(defbitfield (gpgme-sig-notation-flags-t :unsigned-int)
  "The available signature notation flags."
  (:human-readable 1)
  (:critical 2))

(defctype gpgme-sig-notation-t
    (:wrapper :pointer
     :from-c translate-gpgme-sig-notation-t-from-foreign)
  "Signature notation pointer type.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-sig-notation-bitfield :unsigned-int)
  (:human-readable 1)
  (:critical 2))

(defcstruct gpgme-sig-notation
  "Signature notations."
  (next gpgme-sig-notation-t)
  (name :pointer)
  (value :pointer)
  (name-len :int)
  (value-len :int)
  (flags gpgme-sig-notation-flags-t)
  (bitfield gpgme-sig-notation-bitfield))

;;;

(defcenum gpgme-status-code-t
  "The possible status codes for the edit operation."
  (:eof 0)
  (:enter 1)
  (:leave 2)
  (:abort 3)
  (:goodsig 4)
  (:badsig 5)
  (:errsig 6)
  (:badarmor 7)
  (:rsa-or-idea 8)
  (:keyexpired 9)
  (:keyrevoked 10)
  (:trust-undefined 11)
  (:trust-never 12)
  (:trust-marginal 13)
  (:trust-fully 14)
  (:trust-ultimate 15)
  (:shm-info 16)
  (:shm-get 17)
  (:shm-get-bool 18)
  (:shm-get-hidden 19)
  (:need-passphrase 20)
  (:validsig 21)
  (:sig-id 22)
  (:enc-to 23)
  (:nodata 24)
  (:bad-passphrase 25)
  (:no-pubkey 26)
  (:no-seckey 27)
  (:need-passphrase-sym 28)
  (:decryption-failed 29)
  (:decryption-okay 30)
  (:missing-passphrase 31)
  (:good-passphrase 32)
  (:goodmdc 33)
  (:badmdc 34)
  (:errmdc 35)
  (:imported 36)
  (:import-ok 37)
  (:import-problem 38)
  (:import-res 39)
  (:file-start 40)
  (:file-done 41)
  (:file-error 42)
  (:begin-decryption 43)
  (:end-decryption 44)
  (:begin-encryption 45)
  (:end-encryption 46)
  (:delete-problem 47)
  (:get-bool 48)
  (:get-line 49)
  (:get-hidden 50)
  (:got-it 51)
  (:progress 52)
  (:sig-created 53)
  (:session-key 54)
  (:notation-name 55)
  (:notation-data 56)
  (:policy-url 57)
  (:begin-stream 58)
  (:end-stream 59)
  (:key-created 60)
  (:userid-hint 61)
  (:unexpected 62)
  (:inv-recp 63)
  (:no-recp 64)
  (:already-signed 65)
  (:sigexpired 66)
  (:expsig 67)
  (:expkeysig 68)
  (:truncated 69)
  (:error 70)
  (:newsig 71)
  (:revkeysig 72)
  (:sig-subpacket 73)
  (:need-passphrase-pin 74)
  (:sc-op-failure 75)
  (:sc-op-success 76)
  (:cardctrl 77)
  (:backup-key-created 78)
  (:pka-trust-bad 79)
  (:pka-trust-good 80)
  (:plaintext 81)
  (:inv-sgnr 82)
  (:no-sgnr 83)
  (:success 84)
  (:decryption-info 85)
  (:plaintext-length 86)
  (:mountpoint 87)
  (:pinentry-launched 88)
  (:attribute 89)
  (:begin-signing 90)
  (:key-not-created 91)
  (:inquire-maxlen 92)
  (:failure 93)
  (:key-considered 94)
  (:tofu-user 95)
  (:tofu-stats 96)
  (:tofu-stats-long 97)
  (:notation-flags 98)
  (:decryption-compliance-mode 99)
  (:verification-compliance-mode 100))

;;;

(defctype gpgme-engine-info-t
    (:wrapper :pointer
     :from-c translate-gpgme-engine-info-t-to-foreign)
  "The engine information structure pointer type.")

(defcstruct gpgme-engine-info
  "Engine information."
  (next gpgme-engine-info-t)
  (protocol gpgme-protocol-t)
  (file-name :string)
  (version :string)
  (req-version :string)
  (home-dir :string))

;;;

(defctype gpgme-subkey-t
    (:wrapper :pointer
     :from-c translate-gpgme-subkey-t-from-foreign)
  "A subkey from a key.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-subkey-bitfield :unsigned-int)
  "The subkey bitfield."
  (:revoked 1)
  (:expired 2)
  (:disabled 4)
  (:invalid 8)
  (:can-encrypt 16)
  (:can-sign 32)
  (:can-certify 64)
  (:secret 128)
  (:can-authenticate 256)
  (:is-qualified 512)
  (:is-cardkey 1024)
  (:is-de-vs 2048))

(defcstruct gpgme-subkey
  "Subkey from a key."
  (next gpgme-subkey-t)
  (bitfield gpgme-subkey-bitfield)
  (pubkey-algo gpgme-pubkey-algo-t)
  (length :unsigned-int)
  (keyid :string)
  (-keyid :char :count 17)
  (fpr :string)
  (timestamp :long)
  (expires :long))


(defctype gpgme-key-sig-t
    (:wrapper :pointer
     :from-c translate-gpgme-key-sig-t-from-foreign)
  "A signature on a user ID.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-key-sig-bitfield :unsigned-int)
  "The key signature bitfield."
  (:revoked 1)
  (:expired 2)
  (:invalid 4)
  (:exportable 16))

(defcstruct gpgme-key-sig
  "A signature on a user ID."
  (next gpgme-key-sig-t)
  (bitfield gpgme-key-sig-bitfield)
  (pubkey-algo gpgme-pubkey-algo-t)
  (keyid :string)
  (-keyid :char :count 17)
  (timestamp :long)
  (expires :long)
  (status gpgme-error-no-signal-t)
  (-class :unsigned-int)
  (uid :string)
  (name :string)
  (email :string)
  (comment :string)
  (sig-class :unsigned-int))


(defctype gpgme-user-id-t
    (:wrapper :pointer
     :from-c translate-gpgme-user-id-t-from-foreign)
  "A user ID from a key.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-user-id-bitfield :unsigned-int)
  "The user ID bitfield."
  (:revoked 1)
  (:invalid 2))

(defcstruct gpgme-user-id
  "A user ID from a key."
  (next gpgme-user-id-t)
  (bitfield gpgme-user-id-bitfield)
  (validity gpgme-validity-t)
  (uid :string)
  (name :string)
  (email :string)
  (comment :string)
  (signatures gpgme-key-sig-t)
  (-last-keysig gpgme-key-sig-t))


(defctype gpgme-key-t
    (:wrapper :pointer
     :from-c translate-gpgme-key-t-from-foreign
     :to-c translate-gpgme-key-t-to-foreign)
  "A key from the keyring.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-key-bitfield :unsigned-int)
  "The key bitfield."
  (:revoked 1)
  (:expired 2)
  (:disabled 4)
  (:invalid 8)
  (:can-encrypt 16)
  (:can-sign 32)
  (:can-certify 64)
  (:secret 128)
  (:can-authenticate 256)
  (:is-qualified 512))

(defcstruct gpgme-key
  "A signature on a user ID."
  (-refs :unsigned-int)
  (bitfield gpgme-key-bitfield)
  (protocol gpgme-protocol-t)
  (issuer-serial :string)
  (issuer-name :string)
  (chain-id :string)
  (owner-trust gpgme-validity-t)
  (subkeys gpgme-subkey-t)
  (uids gpgme-user-id-t)
  (-last-subkey gpgme-subkey-t)
  (-last-uid gpgme-user-id-t)
  (keylist-mode gpgme-keylist-mode-t))

;;;

;;; There is no support in CFFI to define callback C types and have
;;; automatic type checking with the callback definition.

(defctype gpgme-passphrase-cb-t :pointer)

(defctype gpgme-progress-cb-t :pointer)

(defctype gpgme-edit-cb-t :pointer)


;;;
;;; Function Interface
;;;

;;; Context management functions.

(defcfun ("gpgme_new" c-gpgme-new) gpgme-error-t
  (ctx :pointer))

(defcfun ("gpgme_release" c-gpgme-release) :void
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_set_protocol" c-gpgme-set-protocol) gpgme-error-t
  (ctx gpgme-ctx-t)
  (proto gpgme-protocol-t))

(defcfun ("gpgme_get_protocol" c-gpgme-get-protocol) gpgme-protocol-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_get_protocol_name" c-gpgme-get-protocol-name) :string
  (proto gpgme-protocol-t))

(defcfun ("gpgme_set_armor" c-gpgme-set-armor) :void
  (ctx gpgme-ctx-t)
  (yes :boolean))

(defcfun ("gpgme_get_armor" c-gpgme-get-armor) :boolean
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_set_textmode" c-gpgme-set-textmode) :void
  (ctx gpgme-ctx-t)
  (yes :boolean))

(defcfun ("gpgme_get_textmode" c-gpgme-get-textmode) :boolean
  (ctx gpgme-ctx-t))

(defconstant +include-certs-default+ -256)

(defcfun ("gpgme_set_include_certs" c-gpgme-set-include-certs) :void
  (ctx gpgme-ctx-t)
  (nr-of-certs cert-int-t))

(defcfun ("gpgme_get_include_certs" c-gpgme-get-include-certs) cert-int-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_set_keylist_mode" c-gpgme-set-keylist-mode) gpgme-error-t
  (ctx gpgme-ctx-t)
  (mode gpgme-keylist-mode-t))

(defcfun ("gpgme_get_keylist_mode" c-gpgme-get-keylist-mode)
    gpgme-keylist-mode-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_set_passphrase_cb" c-gpgme-set-passphrase-cb) :void
  (ctx gpgme-ctx-t)
  (cb gpgme-passphrase-cb-t)
  (hook-value :pointer))

(defcfun ("gpgme_get_passphrase_cb" c-gpgme-get-passphrase-cb) :void
  (ctx gpgme-ctx-t)
  (cb-p :pointer)
  (hook-value-p :pointer))

(defcfun ("gpgme_set_progress_cb" c-gpgme-set-progress-cb) :void
  (ctx gpgme-ctx-t)
  (cb gpgme-progress-cb-t)
  (hook-value :pointer))

(defcfun ("gpgme_get_progress_cb" c-gpgme-get-progress-cb) :void
  (ctx gpgme-ctx-t)
  (cb-p :pointer)
  (hook-value-p :pointer))

(defcfun ("gpgme_set_locale" c-gpgme-set-locale) gpgme-error-t
  (ctx gpgme-ctx-t)
  (category :int)
  (value string-or-nil-t))

(defcfun ("gpgme_ctx_get_engine_info" c-gpgme-ctx-get-engine-info)
    gpgme-engine-info-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_ctx_set_engine_info" c-gpgme-ctx-set-engine-info)
    gpgme-error-t
  (ctx gpgme-ctx-t)
  (proto gpgme-protocol-t)
  (file-name string-or-nil-t)
  (home-dir string-or-nil-t))

;;;

(defcfun ("gpgme_pubkey_algo_name" c-gpgme-pubkey-algo-name) :string
  (algo gpgme-pubkey-algo-t))

(defcfun ("gpgme_hash_algo_name" c-gpgme-hash-algo-name) :string
  (algo gpgme-hash-algo-t))

;;;

(defcfun ("gpgme_signers_clear" c-gpgme-signers-clear) :void
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_signers_add" c-gpgme-signers-add) gpgme-error-t
  (ctx gpgme-ctx-t)
  (key gpgme-key-t))

(defcfun ("gpgme_signers_enum" c-gpgme-signers-enum) gpgme-key-t
  (ctx gpgme-ctx-t)
  (seq :int))

;;;

(defcfun ("gpgme_sig_notation_clear" c-gpgme-sig-notation-clear) :void
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_sig_notation_add" c-gpgme-sig-notation-add) gpgme-error-t
  (ctx gpgme-ctx-t)
  (name :string)
  (value string-or-nil-t)
  (flags gpgme-sig-notation-flags-t))

(defcfun ("gpgme_sig_notation_get" c-gpgme-sig-notation-get)
    gpgme-sig-notation-t
  (ctx gpgme-ctx-t))

;;; Run Control.

;;; There is no support in CFFI to define callback C types and have
;;; automatic type checking with the callback definition.

(defctype gpgme-io-cb-t :pointer)

(defctype gpgme-register-io-cb-t :pointer)

(defctype gpgme-remove-io-cb-t :pointer)

(defcenum gpgme-event-io-t
  "The possible events on I/O event callbacks."
  (:start 0)
  (:done 1)
  (:next-key 2)
  (:next-trustitem 3))

(defctype gpgme-event-io-cb-t :pointer)

(defcstruct gpgme-io-cbs
  "I/O callbacks."
  (add gpgme-register-io-cb-t)
  (add-priv :pointer)
  (remove gpgme-remove-io-cb-t)
  (event gpgme-event-io-cb-t)
  (event-priv :pointer))

(defctype gpgme-io-cbs-t :pointer)

(defcfun ("gpgme_set_io_cbs" c-gpgme-set-io-cbs) :void
  (ctx gpgme-ctx-t)
  (io-cbs gpgme-io-cbs-t))

(defcfun ("gpgme_get_io_cbs" c-gpgme-get-io-cbs) :void
  (ctx gpgme-ctx-t)
  (io-cbs gpgme-io-cbs-t))

(defcfun ("gpgme_wait" c-gpgme-wait) gpgme-ctx-t
  (ctx gpgme-ctx-t)
  (status-p :pointer)
  (hang :int))

;;; Functions to handle data objects.

;;; There is no support in CFFI to define callback C types and have
;;; automatic type checking with the callback definition.

(defctype gpgme-data-read-cb-t :pointer)
(defctype gpgme-data-write-cb-t :pointer)
(defctype gpgme-data-seek-cb-t :pointer)
(defctype gpgme-data-release-cb-t :pointer)

(defcstruct gpgme-data-cbs
  "Data callbacks."
  (read gpgme-data-read-cb-t)
  (write gpgme-data-write-cb-t)
  (seek gpgme-data-seek-cb-t)
  (release gpgme-data-release-cb-t))

(defctype gpgme-data-cbs-t :pointer
  "Data callbacks pointer.")

(defcfun ("gpgme_data_read" c-gpgme-data-read) ssize-t
  (dh gpgme-data-t)
  (buffer :pointer)
  (size size-t))

(defcfun ("gpgme_data_write" c-gpgme-data-write) ssize-t
  (dh gpgme-data-t)
  (buffer :pointer)
  (size size-t))

(defcfun ("gpgme_data_seek" c-gpgme-data-seek) off-t
  (dh gpgme-data-t)
  (offset off-t)
  (whence :int))

(defcfun ("gpgme_data_new" c-gpgme-data-new) gpgme-error-t
  (dh-p :pointer))

(defcfun ("gpgme_data_release" c-gpgme-data-release) :void
  (dh gpgme-data-t))

(defcfun ("gpgme_data_new_from_mem" c-gpgme-data-new-from-mem) gpgme-error-t
  (dh-p :pointer)
  (buffer :pointer)
  (size size-t)
  (copy :int))

(defcfun ("gpgme_data_release_and_get_mem" c-gpgme-data-release-and-get-mem)
    :pointer
  (dh gpgme-data-t)
  (len-p :pointer))

(defcfun ("gpgme_data_new_from_cbs" c-gpgme-data-new-from-cbs) gpgme-error-t
  (dh-p :pointer)
  (cbs gpgme-data-cbs-t)
  (handle :pointer))

(defcfun ("gpgme_data_new_from_fd" c-gpgme-data-new-from-fd) gpgme-error-t
  (dh-p :pointer)
  (fd :int))

(defcfun ("gpgme_data_new_from_stream" c-gpgme-data-new-from-stream)
    gpgme-error-t
  (dh-p :pointer)
  (stream :pointer))

(defcfun ("gpgme_data_get_encoding" c-gpgme-data-get-encoding)
    gpgme-data-encoding-t
  (dh gpgme-data-t))

(defcfun ("gpgme_data_set_encoding" c-gpgme-data-set-encoding)
    gpgme-error-t
  (dh gpgme-data-t)
  (enc gpgme-data-encoding-t))

(defcfun ("gpgme_data_get_file_name" c-gpgme-data-get-file-name) :string
  (dh gpgme-data-t))

(defcfun ("gpgme_data_set_file_name" c-gpgme-data-set-file-name) gpgme-error-t
  (dh gpgme-data-t)
  (file-name string-or-nil-t))

(defcfun ("gpgme_data_new_from_file" c-gpgme-data-new-from-file) gpgme-error-t
  (dh-p :pointer)
  (fname :string)
  (copy :int))

(defcfun ("gpgme_data_new_from_filepart" c-gpgme-data-new-from-filepart)
    gpgme-error-t
  (dh-p :pointer)
  (fname :string)
  (fp :pointer)
  (offset off-t)
  (length size-t))

;;; Key and trust functions.

(defcfun ("gpgme_get_key" c-gpgme-get-key) gpgme-error-t
  (ctx gpgme-ctx-t)
  (fpr :string)
  (key-p :pointer)
  (secret :boolean))

(defcfun ("gpgme_key_ref" c-gpgme-key-ref) :void
  (key gpgme-key-t))

(defcfun ("gpgme_key_unref" c-gpgme-key-unref) :void
  (key gpgme-key-t))

;;; Crypto operations.

(defcfun ("gpgme_cancel" c-gpgme-cancel) gpgme-error-t
  (ctx gpgme-ctx-t))

;;;

(defctype gpgme-invalid-key-t
    (:wrapper :pointer
     :from-c translate-gpgme-invalid-key-t-from-foreign)
  "An invalid key structure.")

(defcstruct gpgme-invalid-key
  "An invalid key structure."
  (next gpgme-invalid-key-t)
  (fpr :string)
  (reason gpgme-error-no-signal-t))

;;; Encryption.

(defcstruct gpgme-op-encrypt-result
  "Encryption result structure."
  (invalid-recipients gpgme-invalid-key-t))

(defctype gpgme-op-encrypt-result-t
    (:wrapper :pointer
     :from-c translate-gpgme-op-encrypt-result-t-from-foreign)
  "An encryption result structure.")

(defcfun ("gpgme_op_encrypt_result" c-gpgme-op-encrypt-result)
    gpgme-op-encrypt-result-t
  (ctx gpgme-ctx-t))

(defbitfield gpgme-encrypt-flags-t
  (:always-trust 1)
  (:no-encrypt-to 2)
  (:prepare 4)
  (:expect-sign 8)
  (:no-compress 16)
  (:symmetric 32)
  (:throw-keyids 64)
  (:wrap 128)
  (:want-address 256))

(defcfun ("gpgme_op_encrypt_start" c-gpgme-op-encrypt-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (recp :pointer) ; Key array.
  (flags gpgme-encrypt-flags-t)
  (plain gpgme-data-t)
  (cipher gpgme-data-t))

(defcfun ("gpgme_op_encrypt" c-gpgme-op-encrypt) gpgme-error-t
  (ctx gpgme-ctx-t)
  (recp :pointer) ; Key array.
  (flags gpgme-encrypt-flags-t)
  (plain gpgme-data-t)
  (cipher gpgme-data-t))

(defcfun ("gpgme_op_encrypt_sign_start" c-gpgme-op-encrypt-sign-start)
    gpgme-error-t
  (ctx gpgme-ctx-t)
  (recp :pointer) ; Key array.
  (flags gpgme-encrypt-flags-t)
  (plain gpgme-data-t)
  (cipher gpgme-data-t))

(defcfun ("gpgme_op_encrypt_sign" c-gpgme-op-encrypt-sign) gpgme-error-t
  (ctx gpgme-ctx-t)
  (recp :pointer) ; Key array.
  (flags gpgme-encrypt-flags-t)
  (plain gpgme-data-t)
  (cipher gpgme-data-t))

;;; Decryption.

(defctype gpgme-recipient-t
    (:wrapper :pointer
     :from-c translate-gpgme-recipient-t-from-foreign)
  "A recipient structure.")

(defcstruct gpgme-recipient
  "Recipient structure."
  (next gpgme-recipient-t)
  (keyid :string)
  (-keyid :char :count 17)
  (pubkey-algo gpgme-pubkey-algo-t)
  (status gpgme-error-no-signal-t))

(defbitfield gpgme-op-decrypt-result-bitfield
  "Decryption result structure bitfield."
  (:wrong-key-usage 1)
  (:is-de-vs 2)
  (:is-mine 4))

(defcstruct gpgme-op-decrypt-result
  "Decryption result structure."
  (unsupported-algorithm :string)
  (bitfield gpgme-op-decrypt-result-bitfield)
  (recipients gpgme-recipient-t)
  (file-name :string))

(defctype gpgme-op-decrypt-result-t
    (:wrapper :pointer
     :from-c translate-gpgme-op-decrypt-result-t-from-foreign)
  "A decryption result structure.")

(defcfun ("gpgme_op_decrypt_result" c-gpgme-op-decrypt-result)
    gpgme-op-decrypt-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_decrypt_start" c-gpgme-op-decrypt-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (cipher gpgme-data-t)
  (plain gpgme-data-t))

(defcfun ("gpgme_op_decrypt" c-gpgme-op-decrypt) gpgme-error-t
  (ctx gpgme-ctx-t)
  (cipher gpgme-data-t)
  (plain gpgme-data-t))

(defcfun ("gpgme_op_decrypt_verify_start" c-gpgme-op-decrypt-verify-start)
    gpgme-error-t
  (ctx gpgme-ctx-t)
  (cipher gpgme-data-t)
  (plain gpgme-data-t))

(defcfun ("gpgme_op_decrypt_verify" c-gpgme-op-decrypt-verify) gpgme-error-t
  (ctx gpgme-ctx-t)
  (cipher gpgme-data-t)
  (plain gpgme-data-t))

;;; Signing.

(defctype gpgme-new-signature-t
    (:wrapper :pointer
     :from-c translate-gpgme-new-signature-t-from-foreign)
  "A new signature structure.")

(defcstruct gpgme-new-signature
  "New signature structure."
  (next gpgme-new-signature-t)
  (type gpgme-sig-mode-t)
  (pubkey-algo gpgme-pubkey-algo-t)
  (hash-algo gpgme-hash-algo-t)
  (-obsolete-class :unsigned-long)
  (timestamp :long)
  (fpr :string)
  (-obsolete-class-2 :unsigned-int)
  (sig-class :unsigned-int))

(defcstruct gpgme-op-sign-result
  "Signing result structure."
  (invalid-signers gpgme-invalid-key-t)
  (signatures gpgme-new-signature-t))

(defctype gpgme-op-sign-result-t
    (:wrapper :pointer
     :from-c translate-gpgme-op-sign-result-t-from-foreign)
  "A signing result structure.")

(defcfun ("gpgme_op_sign_result" c-gpgme-op-sign-result)
    gpgme-op-sign-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_sign_start" c-gpgme-op-sign-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (plain gpgme-data-t)
  (sig gpgme-data-t)
  (mode gpgme-sig-mode-t))

(defcfun ("gpgme_op_sign" c-gpgme-op-sign) gpgme-error-t
  (ctx gpgme-ctx-t)
  (plain gpgme-data-t)
  (sig gpgme-data-t)
  (mode gpgme-sig-mode-t))

;;; Verify.

(defbitfield (gpgme-sigsum-t :unsigned-int)
  "Flags used for the summary field in a gpgme-signature-t."
  (:valid #x0001)
  (:green #x0002)
  (:red #x0004)
  (:key-revoked #x0010)
  (:key-expired #x0020)
  (:sig-expired #x0040)
  (:key-missing #x0080)
  (:crl-missing #x0100)
  (:crl-too-old #x0200)
  (:bad-policy #x0400)
  (:sys-error #x0800)
  (:tofu-conflict #x1000))

(defctype gpgme-signature-t
    (:wrapper :pointer
     :from-c translate-gpgme-signature-t-from-foreign)
  "A signature structure.")

;; FIXME: Doesn't this depend on endianness?
(defbitfield (gpgme-signature-bitfield :unsigned-int)
  "The signature bitfield."
  (:wrong-key-usage 1)
  (:pka-trust 2)
  (:chain-model 4)
  (:is-de-vs 8))

(defcstruct gpgme-signature
  "Signature structure."
  (next gpgme-signature-t)
  (summary gpgme-sigsum-t)
  (fpr :string)
  (status gpgme-error-no-signal-t)
  (notations gpgme-sig-notation-t)
  (timestamp :unsigned-long)
  (exp-timestamp :unsigned-long)
  (bitfield gpgme-signature-bitfield)
  (validity gpgme-validity-t)
  (validity-reason gpgme-error-no-signal-t)
  (pubkey-algo gpgme-pubkey-algo-t)
  (hash-algo gpgme-hash-algo-t))

(defcstruct gpgme-op-verify-result
  "Verify result structure."
  (signatures gpgme-signature-t)
  (file-name :string))

(defctype gpgme-op-verify-result-t
    (:wrapper :pointer
     :from-c translate-gpgme-op-verify-result-t-from-foreign)
  "A verify result structure.")

(defcfun ("gpgme_op_verify_result" c-gpgme-op-verify-result)
    gpgme-op-verify-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_verify_start" c-gpgme-op-verify-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (sig gpgme-data-t)
  (signed-text gpgme-data-t)
  (plaintext gpgme-data-t))

(defcfun ("gpgme_op_verify" c-gpgme-op-verify) gpgme-error-t
  (ctx gpgme-ctx-t)
  (sig gpgme-data-t)
  (signed-text gpgme-data-t)
  (plaintext gpgme-data-t))

;;; Import.

(defbitfield (gpgme-import-flags-t :unsigned-int)
  "Flags used for the import status field."
  (:new #x0001)
  (:uid #x0002)
  (:sig #x0004)
  (:subkey #x0008)
  (:secret #x0010))

(defctype gpgme-import-status-t
    (:wrapper :pointer
     :from-c translate-gpgme-import-status-t-from-foreign)
  "An import status structure.")

(defcstruct gpgme-import-status
  "New import status structure."
  (next gpgme-import-status-t)
  (fpr :string)
  (result gpgme-error-no-signal-t)
  (status :unsigned-int))

(defcstruct gpgme-op-import-result
  "Import result structure."
  (considered :int)
  (no-user-id :int)
  (imported :int)
  (imported-rsa :int)
  (unchanged :int)
  (new-user-ids :int)
  (new-sub-keys :int)
  (new-signatures :int)
  (new-revocations :int)
  (secret-read :int)
  (secret-imported :int)
  (secret-unchanged :int)
  (skipped-new-keys :int)
  (not-imported :int)
  (imports gpgme-import-status-t))

(defctype gpgme-op-import-result-t
    (:wrapper :pointer
     :from-c translate-gpgme-op-import-result-t-from-foreign)
  "An import status result structure.")

(defcfun ("gpgme_op_import_result" c-gpgme-op-import-result)
    gpgme-op-import-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_import_start" c-gpgme-op-import-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (keydata gpgme-data-t))

(defcfun ("gpgme_op_import" c-gpgme-op-import) gpgme-error-t
  (ctx gpgme-ctx-t)
  (keydata gpgme-data-t))

;;; Export.

(defcfun ("gpgme_op_export_start" c-gpgme-op-export-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (pattern :string)
  (reserved :unsigned-int)
  (keydata gpgme-data-t))

(defcfun ("gpgme_op_export" c-gpgme-op-export) gpgme-error-t
  (ctx gpgme-ctx-t)
  (pattern :string)
  (reserved :unsigned-int)
  (keydata gpgme-data-t))

;;; FIXME: Extended export interfaces require array handling.

;;; Key generation.

(defbitfield (gpgme-genkey-flags-t :unsigned-int)
  "Flags used for the key generation result bitfield."
  (:primary #x0001)
  (:sub #x0002)
  (:uid #x0004))

(defcstruct gpgme-op-genkey-result
  "Key generation result structure."
  (bitfield gpgme-genkey-flags-t)
  (fpr :string))

(defctype gpgme-op-genkey-result-t :pointer
  "A key generation result structure.")

(defcfun ("gpgme_op_genkey_result" c-gpgme-op-genkey-result)
    gpgme-op-genkey-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_genkey_start" c-gpgme-op-genkey-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (parms :string)
  (pubkey gpgme-data-t)
  (seckey gpgme-data-t))

(defcfun ("gpgme_op_genkey" c-gpgme-op-genkey) gpgme-error-t
  (ctx gpgme-ctx-t)
  (parms :string)
  (pubkey gpgme-data-t)
  (seckey gpgme-data-t))

;;; Key deletion.

(defcfun ("gpgme_op_delete_start" c-gpgme-op-delete-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (key gpgme-key-t)
  (allow-secret :int))

(defcfun ("gpgme_op_delete" c-gpgme-op-delete) gpgme-error-t
  (ctx gpgme-ctx-t)
  (key gpgme-key-t)
  (allow-secret :int))

;;; FIXME: Add edit interfaces.

;;; Keylist interface.

(defbitfield (gpgme-keylist-flags-t :unsigned-int)
  "Flags used for the key listing result bitfield."
  (:truncated #x0001))

(defcstruct gpgme-op-keylist-result
  "Key listing result structure."
  (bitfield gpgme-keylist-flags-t))

(defctype gpgme-op-keylist-result-t :pointer
  "A key listing result structure.")

(defcfun ("gpgme_op_keylist_result" c-gpgme-op-keylist-result)
    gpgme-op-keylist-result-t
  (ctx gpgme-ctx-t))

(defcfun ("gpgme_op_keylist_start" c-gpgme-op-keylist-start) gpgme-error-t
  (ctx gpgme-ctx-t)
  (pattern :string)
  (secret_only :boolean))

;;; FIXME: Extended keylisting requires array handling.

(defcfun ("gpgme_op_keylist_next" c-gpgme-op-keylist-next) gpgme-error-t
  (ctx gpgme-ctx-t)
  (r-key :pointer))

(defcfun ("gpgme_op_keylist_end" c-gpgme-op-keylist-end) gpgme-error-t
  (ctx gpgme-ctx-t))

;;; Various functions.

(defcfun ("gpgme_check_version" c-gpgme-check-version) :string
  (req-version string-or-nil-t))

(defcfun ("gpgme_get_engine_info" c-gpgme-get-engine-info) gpgme-error-t
  (engine-info-p :pointer))

(defcfun ("gpgme_set_engine_info" c-gpgme-set-engine-info) gpgme-error-t
  (proto gpgme-protocol-t)
  (file-name string-or-nil-t)
  (home-dir string-or-nil-t))

(defcfun ("gpgme_engine_check_version" c-gpgme-engine-check-verson)
    gpgme-error-t
  (proto gpgme-protocol-t))

;;;
;;;  L I S P   I N T E R F A C E
;;;

;;;
;;; Lisp type translators.
;;;

;;; Both directions.

;;; cert-int-t is a helper type that takes care of representing the
;;; default number of certs as NIL.

(defun translate-cert-int-t-from-foreign (value)
  (cond
    ((eql value +include-certs-default+) nil)
    (t value)))

(defun translate-cert-int-t-to-foreign (value)
  (cond
    (value value)
    (t +include-certs-default+)))

;;; string-or-nil-t translates a null pointer to NIL and vice versa.
;;; Translation from foreign null pointer already works as expected.

(defun translate-string-or-nil-t-to-foreign (value)
  (cond
    (value value)
    (t (null-pointer))))

;;; Output only.

;;; These type translators only convert from foreign type, because we
;;; never use these types in the other direction.

;;; Convert gpgme-engine-info-t linked lists into a list of property
;;; lists.  Note that this converter will automatically be invoked
;;; recursively.
;;;
;;; FIXME: Should we use a hash table (or struct, or clos) instead of
;;; property list, as recommended by the Lisp FAQ?

(defun translate-gpgme-engine-info-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next protocol file-name version req-version home-dir)
	    value (:struct gpgme-engine-info))
	 (append (list protocol (list
			     :file-name file-name
			     :version version
			     :req-version req-version
			     :home-dir home-dir))
		 next)))))

(defun translate-gpgme-invalid-key-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next fpr reason)
	    value (:struct gpgme-invalid-key))
	 (append (list (list :fpr fpr
			     :reason reason))
		 next)))))

(defun translate-gpgme-op-encrypt-result-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((invalid-recipients)
	    value (:struct gpgme-op-encrypt-result))
	 (list :encrypt
	       (list :invalid-recipients invalid-recipients))))))

(defun translate-gpgme-recipient-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next keyid pubkey-algo status)
	    value (:struct gpgme-recipient))
	 (append (list (list :keyid keyid
			     :pubkey-algo pubkey-algo
			     :status status))
		 next)))))

(defun translate-gpgme-op-decrypt-result-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((unsupported-algorithm bitfield recipients file-name)
	    value (:struct gpgme-op-decrypt-result))
	 (list :decrypt (list :unsupported-algorithm unsupported-algorithm
			      :bitfield bitfield
			      :recipients recipients
			      :file-name file-name))))))

(defun translate-gpgme-new-signature-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next type pubkey-algo hash-algo timestamp fpr sig-class)
	    value (:struct gpgme-new-signature))
	 (append (list (list :type type
			     :pubkey-algo pubkey-algo
			     :hash-algo hash-algo
			     :timestamp timestamp
			     :fpr fpr
			     :sig-class sig-class))
		 next)))))

(defun translate-gpgme-op-sign-result-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((invalid-signers signatures)
	    value (:struct gpgme-op-sign-result))
	 (list :sign (list :invalid-signers invalid-signers
			   :signatures signatures))))))

(defun translate-gpgme-signature-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next summary fpr status notations timestamp
		  exp-timestamp bitfield validity validity-reason
		  pubkey-algo hash-algo)
	    value (:struct gpgme-signature))
	 (append (list (list :summary summary
			     :fpr fpr
			     :status status
			     :notations notations
			     :timestamp timestamp
			     :exp-timestamp exp-timestamp
			     :bitfield bitfield
			     :validity validity
			     :validity-reason validity-reason
			     :pubkey-algo pubkey-algo))
		 next)))))

(defun translate-gpgme-op-verify-result-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((signatures file-name)
	    value (:struct gpgme-op-verify-result))
	 (list :verify (list :signatures signatures
			     :file-name file-name))))))

(defun translate-gpgme-import-status-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next fpr result status)
	    value (:struct gpgme-import-status))
	 (append (list (list :fpr fpr
			     :result result
			     :status status))
		 next)))))

(defun translate-gpgme-op-import-result-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((considered no-user-id imported imported-rsa unchanged
			new-user-ids new-sub-keys new-signatures
			new-revocations secret-read secret-imported
			secret-unchanged skipped-new-keys not-imported
			imports)
	    value (:struct gpgme-op-import-result))
	 (list :verify (list :considered considered
			     :no-user-id no-user-id
			     :imported imported
			     :imported-rsa imported-rsa
			     :unchanged unchanged
			     :new-user-ids new-user-ids
			     :new-sub-keys new-sub-keys
			     :new-signatures new-signatures
			     :new-revocations new-revocations
			     :secret-read secret-read
			     :secret-imported secret-imported
			     :secret-unchanged secret-unchanged
			     :skipped-new-keys skipped-new-keys
			     :not-imported not-imported
			     :imports imports))))))

;;; Error handling.

;;; Use gpgme-error-no-signal-t to suppress automatic error handling
;;; at translation time.
;;;
;;; FIXME: Part of this probably should be in gpg-error!

(define-condition gpgme-error (error)
  ((value :initarg :gpgme-error :reader gpgme-error-value))
  (:report (lambda (c stream)
	     (format stream "GPGME returned error: ~A (~A)"
		     (gpgme-strerror (gpgme-error-value c))
		     (gpgme-strsource (gpgme-error-value c)))))
  (:documentation "Signalled when a GPGME function returns an error."))

(defun translate-gpgme-error-t-from-foreign (value)
  "Raise a GPGME-ERROR if VALUE is non-zero."
  (when (not (eql (gpgme-err-code value) :gpg-err-no-error))
    (error 'gpgme-error :gpgme-error value))
  (gpg-err-canonicalize value))

(defun translate-gpgme-error-t-to-foreign (value)
  "Canonicalize the error value."
  (if (eql (gpgme-err-code value) :gpg-err-no-error)
      0
      (gpg-err-as-value value)))

(defun translate-gpgme-error-no-signal-t-from-foreign (value)
  "Canonicalize the error value."
  (gpg-err-canonicalize value))


;;; *INTERNAL* Lispy Function Interface that is still close to the C
;;; interface.

;;; Passphrase callback management.

;;; Maybe: Instead, use subclassing, and provide a customizable
;;; default implementation for ease-of-use.

(defvar *passphrase-handles* (make-hash-table)
  "Hash table with GPGME context address as key and the corresponding
   passphrase callback object as value.")

(defcallback passphrase-cb gpgme-error-t ((handle :pointer)
					  (uid-hint :string)
					  (passphrase-info :string)
					  (prev-was-bad :boolean)
					  (fd :int))
  (handler-case
      (let* ((passphrase-cb
	      (gethash (pointer-address handle) *passphrase-handles*))
	     (passphrase
	      (cond
		((functionp passphrase-cb)
		 (concatenate 'string
			      (funcall passphrase-cb uid-hint passphrase-info
				       prev-was-bad)
			      '(#\Newline)))
		(t (concatenate 'string passphrase-cb '(#\Newline)))))
	     (passphrase-len (length passphrase))
	     ;; FIXME: Could be more robust.
	     (res (system-write fd passphrase passphrase-len)))
	(cond
	  ((< res passphrase-len) ; FIXME: Blech.  A weak attempt to be robust.
	   (gpgme-error :gpg-err-inval))
	  (t (gpgme-error :gpg-err-no-error))))
    (gpgme-error (err) (gpgme-error-value err))
    (system-error (err) (gpgme-error-from-errno (system-error-errno err)))
    ;; FIXME: The original error gets lost here.  
    (condition (err) (progn
		       (when *debug*
			 (format t "DEBUG: passphrase-cb: Unexpressable: ~A~%"
				 err))
		       (gpgme-error :gpg-err-general)))))

;;; CTX is a C-pointer to the context.
(defun gpgme-set-passphrase-cb (ctx cb)
  "Set the passphrase callback for CTX."
  (let ((handle (pointer-address ctx)))
    (cond
      (cb (setf (gethash handle *passphrase-handles*) cb)
	  (c-gpgme-set-passphrase-cb ctx (callback passphrase-cb) ctx))
      (t (c-gpgme-set-passphrase-cb ctx (null-pointer) (null-pointer))
	 (remhash handle *passphrase-handles*)))))

;;; Progress callback management.

;;; Maybe: Instead, use subclassing, and provide a customizable
;;; default implementation for ease-of-use.

(defvar *progress-handles* (make-hash-table)
  "Hash table with GPGME context address as key and the corresponding
   progress callback object as value.")

(defcallback progress-cb :void ((handle :pointer)
				(what :string)
				(type :int)
				(current :int)
				(total :int))
  (handler-case
      (let* ((progress-cb
	      (gethash (pointer-address handle) *progress-handles*)))
	(funcall progress-cb what type current total))
    ;; FIXME: The original error gets lost here.  
    (condition (err) (when *debug*
		       (format t "DEBUG: progress-cb: Unexpressable: ~A~%"
			       err)))))

;;; CTX is a C-pointer to the context.
(defun gpgme-set-progress-cb (ctx cb)
  "Set the progress callback for CTX."
  (let ((handle (pointer-address ctx)))
    (cond
      (cb (setf (gethash handle *progress-handles*) cb)
	  (c-gpgme-set-progress-cb ctx (callback progress-cb) ctx))
      (t (c-gpgme-set-progress-cb ctx (null-pointer) (null-pointer))
	 (remhash handle *progress-handles*)))))

;;; Context management.

(defun gpgme-new (&key (protocol :openpgp) armor textmode include-certs
		  keylist-mode passphrase progress file-name home-dir)
  "Allocate a new GPGME context."
  (with-foreign-object (ctx-p 'gpgme-ctx-t)
    (c-gpgme-new ctx-p)
    (let ((ctx (mem-ref ctx-p 'gpgme-ctx-t)))
      ;;; Set locale?
      (gpgme-set-protocol ctx protocol)
      (gpgme-set-armor ctx armor)
      (gpgme-set-textmode ctx textmode)
      (when include-certs (gpgme-set-include-certs ctx include-certs))
      (when keylist-mode (gpgme-set-keylist-mode ctx keylist-mode))
      (gpgme-set-passphrase-cb ctx passphrase)
      (gpgme-set-progress-cb ctx progress)
      (gpgme-set-engine-info ctx protocol
			     :file-name file-name :home-dir home-dir)
      (when *debug* (format t "DEBUG: gpgme-new: ~A~%" ctx))
      ctx)))

(defun gpgme-release (ctx)
  "Release a GPGME context."
  (when *debug* (format t "DEBUG: gpgme-release: ~A~%" ctx))
  (c-gpgme-release ctx))

(defun gpgme-set-protocol (ctx proto)
  "Set the protocol to be used by CTX to PROTO."
  (c-gpgme-set-protocol ctx proto))

(defun gpgme-get-protocol (ctx)
  "Get the protocol used with CTX."
  (c-gpgme-get-protocol ctx))

;;; FIXME: How to do pretty printing?
;;;
;;; gpgme-get-protocol-name

(defun gpgme-set-armor (ctx armor)
  "If ARMOR is true, enable armor mode in CTX, disable it otherwise."
 (c-gpgme-set-armor ctx armor))

(defun gpgme-armor-p (ctx)
  "Return true if armor mode is set for CTX."
  (c-gpgme-get-armor ctx))

(defun gpgme-set-textmode (ctx textmode)
  "If TEXTMODE is true, enable text mode mode in CTX, disable it otherwise."
 (c-gpgme-set-textmode ctx textmode))

(defun gpgme-textmode-p (ctx)
  "Return true if text mode mode is set for CTX."
  (c-gpgme-get-textmode ctx))

(defun gpgme-set-include-certs (ctx &optional certs)
  "Include up to CERTS certificates in an S/MIME message."
  (c-gpgme-set-include-certs ctx certs))

(defun gpgme-get-include-certs (ctx)
  "Return the number of certs to include in an S/MIME message,
   or NIL if the default is used."
  (c-gpgme-get-include-certs ctx))

(defun gpgme-get-keylist-mode (ctx)
  "Get the keylist mode in CTX."
  (c-gpgme-get-keylist-mode ctx))

(defun gpgme-set-keylist-mode (ctx mode)
  "Set the keylist mode in CTX."
  (c-gpgme-set-keylist-mode ctx mode))


;;; FIXME: How to handle locale?  cffi-grovel?

(defun gpgme-get-engine-info (&optional ctx)
  "Retrieve the engine info for CTX, or the default if CTX is omitted."
  (cond
    (ctx (c-gpgme-ctx-get-engine-info ctx))
    (t (with-foreign-object (info-p 'gpgme-engine-info-t)
	 (c-gpgme-get-engine-info info-p)
	 (mem-ref info-p 'gpgme-engine-info-t)))))

(defun gpgme-set-engine-info (ctx proto &key file-name home-dir)
  "Set the engine info for CTX, or the default if CTX is NIL."
  (cond
    (ctx (c-gpgme-ctx-set-engine-info ctx proto file-name home-dir))
    (t (c-gpgme-set-engine-info proto file-name home-dir))))

;;; FIXME: How to do pretty printing?
;;;
;;; gpgme_pubkey_algo_name, gpgme_hash_algo_name

(defun gpgme-set-signers (ctx keys)
  "Set the signers for the context CTX."
  (c-gpgme-signers-clear ctx)
  (dolist (key keys) (c-gpgme-signers-add ctx key)))

;;;

(defun gpgme-set-sig-notation (ctx notations)
  "Set the sig notation for the context CTX."
  (c-gpgme-sig-notation-clear ctx)
  (dolist (notation notations)
    (c-gpgme-sig-notation-add
     ctx (first notation) (second notation) (third notation))))

(defun gpgme-get-sig-notation (ctx)
  "Get the signature notation data for the context CTX."
  (c-gpgme-sig-notation-get ctx))

;;; FIXME: Add I/O callback interface, for integration with clg.

;;; FIXME: Add gpgme_wait?

;;; Streams
;;; -------
;;;
;;; GPGME uses standard streams.  You can define your own streams, or
;;; use the existing file or string streams.
;;;
;;; A stream-spec is either a stream, or a list with a stream as its
;;; first argument followed by keyword parameters: encoding,
;;; file-name.
;;;
;;; FIXME: Eventually, we should provide a class that can be mixed
;;; into stream classes and which provides accessors for encoding and
;;; file-names.  This interface should be provided in addition to the
;;; above sleazy interface, because the sleazy interface is easier to
;;; use (less typing), and is quite sufficient in a number of cases.
;;;
;;; For best results, streams with element type (unsigned-byte 8)
;;; should be used.  Character streams may work if armor mode is used.

;;; Do we need to provide access to GPGME data objects through streams
;;; as well?  It seems to me that specific optimizations, like
;;; directly writing to file descriptors, is better done by extending
;;; the sleazy syntax (stream-spec) instead of customized streams.
;;; Customized streams do buffering, and this may mess up things.  Mmh.

(defvar *data-handles* (make-hash-table)
  "Hash table with GPGME data user callback handle address as key
   and the corresponding stream as value.")

;;; The release callback removes the stream from the *data-handles*
;;; hash and releases the CBS structure that is used as the key in
;;; that hash.  It is implicitly invoked (through GPGME) by
;;; gpgme-data-release.
(defcallback data-release-cb :void ((handle :pointer))
  (unwind-protect (remhash (pointer-address handle) *data-handles*)
    (when (not (null-pointer-p handle)) (foreign-free handle))))

(defcallback data-read-cb ssize-t ((handle :pointer) (buffer :pointer)
                                   (size size-t))
  (when *debug* (format t "DEBUG: gpgme-data-read-cb: want ~A~%" size))
  (let ((stream (gethash (pointer-address handle) *data-handles*)))
    (cond
      (stream
       (let* ((stream-type (stream-element-type stream))
              (seq (make-array size :element-type stream-type))
              (read (read-sequence seq stream)))
         (cond
           ((equal stream-type '(unsigned-byte 8))
            (dotimes (i read)
              (setf (mem-aref buffer :unsigned-char i)
                    (aref (the byte-array seq) i))))
           ((eql stream-type 'character)
            (dotimes (i read)
              (setf (mem-aref buffer :unsigned-char i)
                    (char-code (aref (the character-array seq) i)))))
           (t
            (dotimes (i read)
              (setf (mem-aref buffer :unsigned-char i)
                    (coerce (aref seq i) '(unsigned-byte 8))))))
         (when *debug* (format t "DEBUG: gpgme-data-read-cb: read ~A~%" read))
         read))
      (t
       (set-errno +ebadf+)
       -1))))

(defcallback data-write-cb ssize-t ((handle :pointer) (buffer :pointer)
                                    (size size-t))
  (when *debug* (format t "DEBUG: gpgme-data-write-cb: want ~A~%" size))
  (let ((stream (gethash (pointer-address handle) *data-handles*)))
    (cond
      (stream
       (let* ((stream-type (stream-element-type stream))
              (seq (make-array size :element-type stream-type)))
         (cond
           ((equal stream-type '(unsigned-byte 8))
            (dotimes (i size)
              (setf (aref (the byte-array seq) i)
                    (mem-aref buffer :unsigned-char i))))
           ((eql stream-type 'character)
            (dotimes (i size)
              (setf (aref (the character-array seq) i)
                    (code-char (mem-aref buffer :unsigned-char i)))))
           (t
            (dotimes (i size)
              (setf (aref seq i)
                    (coerce (mem-aref buffer :unsigned-char i) stream-type)))))
         (write-sequence seq stream)
         size))
      (t
       (set-errno +ebadf+)
       -1))))

;;; This little helper macro allows us to swallow the cbs structure by
;;; simply setting it to a null pointer, but still protect against
;;; conditions.
(defmacro with-cbs-swallowed ((cbs) &body body)
  `(let ((,cbs (foreign-alloc '(:struct gpgme-data-cbs))))
    (unwind-protect (progn ,@body)
      (when (not (null-pointer-p ,cbs)) (foreign-free ,cbs)))))

(defun gpgme-data-new (stream &key encoding file-name)
  "Allocate a new GPGME data object for STREAM."
  (with-foreign-object (dh-p 'gpgme-data-t)
    ;;; We allocate one CBS structure for each stream we wrap in a
    ;;; data object.  Although we could also share all these
    ;;; structures, as they contain the very same callbacks, we need a
    ;;; unique C pointer as handle anyway to look up the stream in the
    ;;; callback.  This is a convenient one to use.
    (with-cbs-swallowed (cbs)
      (setf (foreign-slot-value cbs '(:struct gpgme-data-cbs) 'read)
            (callback data-read-cb))
      (setf (foreign-slot-value cbs '(:struct gpgme-data-cbs) 'write)
            (callback data-write-cb))
      (setf (foreign-slot-value cbs '(:struct gpgme-data-cbs) 'seek)
            (null-pointer))
      (setf (foreign-slot-value cbs '(:struct gpgme-data-cbs) 'release)
            (callback data-release-cb))
      (c-gpgme-data-new-from-cbs dh-p cbs cbs)
      (let ((dh (mem-ref dh-p 'gpgme-data-t)))
	(when encoding (gpgme-data-set-encoding dh encoding))
	(when file-name (gpgme-data-set-file-name dh file-name))
	;;; Install the stream into the hash table and swallow the cbs
        ;;; structure while protecting against any errors.
	(unwind-protect
	     (progn
	       (setf (gethash (pointer-address cbs) *data-handles*) stream)
	       (setf cbs (null-pointer)))
	  (when (not (null-pointer-p cbs)) (c-gpgme-data-release dh)))
	(when *debug* (format t "DEBUG: gpgme-data-new: ~A~%" dh))
	dh))))

;;; This function releases a GPGME data object.  It implicitly
;;; invokes the data-release-cb function to clean up associated junk.
(defun gpgme-data-release (dh)
  "Release a GPGME data object."
  (when *debug* (format t "DEBUG: gpgme-data-release: ~A~%" dh))
  (c-gpgme-data-release dh))

(defclass data ()
  (c-data)  ; The C data object pointer
  (:documentation "The GPGME data type."))

(defmethod initialize-instance :after ((data data) &key streamspec
                                       &allow-other-keys)
  (let ((c-data (if (listp streamspec)
                    (apply #'gpgme-data-new streamspec)
                    (gpgme-data-new streamspec)))
        (cleanup t))
    (unwind-protect
         (progn
           (setf (slot-value data 'c-data) c-data)
           (finalize data (lambda () (gpgme-data-release c-data)))
           (setf cleanup nil))
      (if cleanup (gpgme-data-release c-data)))))

(defun translate-gpgme-data-t-to-foreign (value)
  ;; Allow a pointer to be passed directly for the finalizer to work.
  (cond
    ((null value) (null-pointer))
    ((pointerp value) value)
    (t (slot-value value 'c-data))))

(defmacro with-gpgme-data ((dh streamspec) &body body)
  `(let ((,dh (make-instance 'data :streamspec ,streamspec)))
     ,@body))

(defun gpgme-data-get-encoding (dh)
  "Get the encoding associated with the data object DH."
  (c-gpgme-data-get-encoding dh))

(defun gpgme-data-set-encoding (dh encoding)
  "Set the encoding associated with the data object DH to ENCODING."
  (c-gpgme-data-set-encoding dh encoding))

(defun gpgme-data-get-file-name (dh)
  "Get the file name associated with the data object DH."
  (c-gpgme-data-get-file-name dh))

(defun gpgme-data-set-file-name (dh file-name)
  "Set the file name associated with the data object DH to FILE-NAME."
  (c-gpgme-data-set-file-name dh file-name))

;;; FIXME: Add key accessor interfaces.

(defun gpgme-get-key (ctx fpr &optional secret)
  "Get the key with the fingerprint FPR from the context CTX."
  (with-foreign-object (key-p 'gpgme-key-t)
    (c-gpgme-get-key ctx fpr key-p secret)
    (mem-ref key-p 'gpgme-key-t)))

(defun gpgme-key-ref (key)
  "Acquire an additional reference to the key KEY."
  (when *debug* (format t "DEBUG: gpgme-key-ref: ~A~%" key))
  (c-gpgme-key-ref key))

(defun gpgme-key-unref (key)
  "Release a reference to the key KEY."
  (when *debug* (format t "DEBUG: gpgme-key-unref: ~A~%" key))
  (c-gpgme-key-unref key))

;;; FIXME: We REALLY need pretty printing for keys and all the other
;;; big structs.

;;; Various interfaces.

(defun gpgme-check-version (&optional req-version)
  (c-gpgme-check-version req-version))

;;;
;;; The *EXPORTED* CLOS interface.
;;;

;;; The context type.

;;; We wrap the C context pointer into a class object to be able to
;;; stick a finalizer on it.

(defclass context ()
  (c-ctx  ; The C context object pointer.
   signers ; The list of signers.
   sig-notation) ; The list of signers.
  (:documentation "The GPGME context type."))

(defmethod initialize-instance :after ((ctx context) &rest rest
				       &key &allow-other-keys)
  (let ((c-ctx (apply #'gpgme-new rest))
	(cleanup t))
    (unwind-protect
	 (progn (setf (slot-value ctx 'c-ctx) c-ctx)
		(finalize ctx (lambda () (gpgme-release c-ctx)))
		(setf cleanup nil))
      (if cleanup (gpgme-release c-ctx)))))

(defun translate-gpgme-ctx-t-to-foreign (value)
  ;; Allow a pointer to be passed directly for the finalizer to work.
  (if (pointerp value) value (slot-value value 'c-ctx)))

(defmacro context (&rest rest)
  "Create a new GPGME context."
  `(make-instance 'context ,@rest))

;;; The context type: Accessor functions.

;;; The context type: Accessor functions: Protocol.

(defgeneric protocol (ctx)
  (:documentation "Get the protocol of CONTEXT."))

(defmethod protocol ((ctx context))
  (gpgme-get-protocol ctx))

(defgeneric (setf protocol) (protocol ctx)
  (:documentation "Set the protocol of CONTEXT to PROTOCOL."))

;;; FIXME: Adjust translator to reject invalid protocols.  Currently,
;;; specifying an invalid protocol throws a "NIL is not 32 signed int"
;;; error.  This is suboptimal.
(defmethod (setf protocol) (protocol (ctx context))
  (gpgme-set-protocol ctx protocol))

;;; The context type: Accessor functions: Armor.
;;; FIXME: Is it good style to make foop setf-able?  Or should it be
;;; foo/foop for set/get?

(defgeneric armorp (ctx)
  (:documentation "Get the armor flag of CONTEXT."))

(defmethod armorp ((ctx context))
  (gpgme-armor-p ctx))

(defgeneric (setf armorp) (armor ctx)
  (:documentation "Set the armor flag of CONTEXT to ARMOR."))

(defmethod (setf armorp) (armor (ctx context))
  (gpgme-set-armor ctx armor))

;;; The context type: Accessor functions: Textmode.
;;; FIXME: Is it good style to make foop setf-able?  Or should it be
;;; foo/foop for set/get?

(defgeneric textmodep (ctx)
  (:documentation "Get the text mode flag of CONTEXT."))

(defmethod textmodep ((ctx context))
  (gpgme-textmode-p ctx))

(defgeneric (setf textmodep) (textmode ctx)
  (:documentation "Set the text mode flag of CONTEXT to TEXTMODE."))

(defmethod (setf textmodep) (textmode (ctx context))
  (gpgme-set-textmode ctx textmode))

;;; The context type: Accessor functions: Include Certs.

(defgeneric include-certs (ctx)
  (:documentation "Get the number of included certificates in an
                   S/MIME message, or NIL if the default is used."))

(defmethod include-certs ((ctx context))
  (gpgme-get-include-certs ctx))

(defgeneric (setf include-certs) (certs ctx)
  (:documentation "Return the number of certificates to include in an
                   S/MIME message, or NIL if the default is used."))

(defmethod (setf include-certs) (certs (ctx context))
  (gpgme-set-include-certs ctx certs))

;;; The context type: Accessor functions: Engine info.

(defgeneric engine-info (ctx)
  (:documentation "Retrieve the engine info for CTX."))

(defmethod engine-info ((ctx context))
  (gpgme-get-engine-info ctx))

(defgeneric (setf engine-info) (info ctx)
  (:documentation "Set the engine info for CTX."))

(defmethod (setf engine-info) (info (ctx context))
  (dolist (proto '(:openpgp :cms))
    (let ((pinfo (getf info proto)))
      (when pinfo
	(gpgme-set-engine-info ctx proto :file-name (getf pinfo :file-name)
			       :home-dir (getf pinfo :home-dir))))))

;;; The context type: Accessor functions: Keylist mode.

(defgeneric keylist-mode (ctx)
  (:documentation "Get the keylist mode of CTX."))

(defmethod keylist-mode ((ctx context))
  (gpgme-get-keylist-mode ctx))

(defgeneric (setf keylist-mode) (mode ctx)
  (:documentation "Set the keylist mode of CTX to MODE."))

(defmethod (setf keylist-mode) (mode (ctx context))
  (gpgme-set-keylist-mode ctx mode))

;;; The context type: Accessor functions: Signers.

(defgeneric signers (ctx)
  (:documentation "Get the signers of CTX."))

(defmethod signers ((ctx context))
  (slot-value ctx 'signers))

(defgeneric (setf signers) (signers ctx)
  (:documentation "Set the signers of CTX to SIGNERS."))

(defmethod (setf keylist-mode) (signers (ctx context))
  (gpgme-set-signers ctx signers)
  (setf (slot-value ctx 'signers) signers))

;;; The context type: Accessor functions: Sig notations.

(defgeneric sig-notations (ctx)
  (:documentation "Get the signature notations of CTX."))

(defmethod sig-notations ((ctx context))
  (slot-value ctx 'signers))

(defgeneric (setf sig-notations) (notations ctx)
  (:documentation "Set the signatire notations of CTX to NOTATIONS."))

(defmethod (setf sig-notations) (notations (ctx context))
  (gpgme-set-signers ctx notations)
  (setf (slot-value ctx 'notations) notations))

;;; The context type: Support macros.

(defmacro with-context ((ctx &rest rest) &body body)
  `(let ((,ctx (make-instance 'context ,@rest)))
    ,@body))

;;; The key type.

(defclass key ()
  (c-key)  ; The C key object pointer.
  (:documentation "The GPGME key type."))

;;; In the initializer, we swallow the c-key argument.
(defmethod initialize-instance :after ((key key) &key c-key
				       &allow-other-keys)
  (setf (slot-value key 'c-key) c-key)
  (finalize key (lambda () (gpgme-key-unref c-key))))

(defun translate-gpgme-key-t-from-foreign (value)
  (when *debug* (format t "DEBUG: import key: ~A~%" value))
  (make-instance 'key :c-key value))

(defun translate-gpgme-key-t-to-foreign (value)
  ;; Allow a pointer to be passed directly for the finalizer to work.
  (if (pointerp value) value (slot-value value 'c-key)))

(defmethod print-object ((key key) stream)
  (print-unreadable-object (key stream :type t :identity t)
    (format stream "~s" (fpr key))))

;;; The key type: Accessor functions.

;;; FIXME: The bitfield and flags contain redundant information at
;;; this point.  FIXME: Deal nicer with zero-length name (policy url)
;;; and zero length value (omit?) and human-readable (convert to string).
;;; FIXME: Turn binary data into sequence or vector or what it should be.
;;; FIXME: Turn the whole thing into a hash?
(defun translate-gpgme-sig-notation-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next name value name-len value-len flags bitfield)
	    value (:struct gpgme-sig-notation))
	 (append (list (list
			:name name
			:value value
			:name-len name-len
			:value-len value-len
			:flags flags
			:bitfield bitfield))
		 next)))))

;;; FIXME: Deal nicer with timestamps.  bitfield field name?
(defun translate-gpgme-subkey-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next bitfield pubkey-algo length keyid fpr timestamp expires)
	    value (:struct gpgme-subkey))
	 (append (list (list
			:bitfield bitfield
			:pubkey-algo pubkey-algo
			:length length
			:keyid keyid
			:fpr fpr
			:timestamp timestamp
			:expires expires))
		 next)))))

(defun translate-gpgme-key-sig-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next bitfield pubkey-algo keyid timestamp expires status
		  uid name email comment sig-class)
	    value (:struct gpgme-key-sig))
	 (append (list (list
			:bitfield bitfield
			:pubkey-algo pubkey-algo
			:keyid keyid
			:timestamp timestamp
			:expires expires
			:status status
			:uid uid
			:name name
			:email email
			:comment comment
			:sig-class sig-class))
		 next)))))

(defun translate-gpgme-user-id-t-from-foreign (value)
  (cond
    ((null-pointer-p value) nil)
    (t (with-foreign-slots
	   ((next bitfield validity uid name email comment signatures)
	    value (:struct gpgme-user-id))
	 (append (list (list
			:bitfield bitfield
			:validity validity
			:uid uid
			:name name
			:email email
			:comment comment
			:signatures signatures))
		 next)))))

(defun key-data (key)
  (with-slots (c-key) key
    (with-foreign-slots
	((bitfield protocol issuer-serial issuer-name chain-id
		   owner-trust subkeys uids keylist-mode)
	 c-key (:struct gpgme-key))
      (list
       :bitfield bitfield
       :protocol protocol
       :issuer-serial issuer-serial
       :issuer-name issuer-name
       :chain-id chain-id
       :owner-trust owner-trust
       :subkeys subkeys
       :uids uids
       :keylist-mode keylist-mode))
    ))


(defgeneric fpr (key)
  (:documentation "Get the primary fingerprint of the key."))

(defmethod fpr ((key key))
  (getf (car (getf (key-data key) :subkeys)) :fpr))


;;; The context type: Crypto-Operations.

(defgeneric get-key (ctx fpr &optional secret)
  (:documentation "Get the (secret) key FPR from CTX."))

(defmethod get-key ((ctx context) fpr &optional secret)
  (gpgme-get-key ctx fpr secret))

;;; Encrypt.

(defgeneric op-encrypt (ctx recp plain cipher &key always-trust sign)
  (:documentation "Encrypt."))

(defmethod op-encrypt ((ctx context) recp plain cipher
		       &key always-trust sign)
  (with-foreign-object (c-recp :pointer (+ 1 (length recp)))
    (dotimes (i (length recp))
      (setf (mem-aref c-recp 'gpgme-key-t i) (elt recp i)))
    (setf (mem-aref c-recp :pointer (length recp)) (null-pointer))
    (with-gpgme-data (in plain)
      (with-gpgme-data (out cipher)
	(let ((flags))
	  (if always-trust (push :always-trust flags))
	  (cond
	    (sign
	     (c-gpgme-op-encrypt-sign ctx c-recp flags in out)
	     (append (c-gpgme-op-encrypt-result ctx)
		     (c-gpgme-op-sign-result ctx)))
	    (t
	     (c-gpgme-op-encrypt ctx c-recp flags in out)
	     (c-gpgme-op-encrypt-result ctx))))))))

;;; Decrypt.

(defgeneric op-decrypt (ctx cipher plain &key verify)
  (:documentation "Decrypt."))

(defmethod op-decrypt ((ctx context) cipher plain &key verify)
  (with-gpgme-data (in cipher)
    (with-gpgme-data (out plain)
      (cond
	(verify
	 (c-gpgme-op-decrypt-verify ctx in out)
	 (append (c-gpgme-op-decrypt-result ctx)
		 (c-gpgme-op-verify-result ctx)))
	(t
	 (c-gpgme-op-decrypt ctx in out)
	 (c-gpgme-op-decrypt-result ctx))))))

;;; Signing.

(defgeneric op-sign (ctx plain sig &optional mode)
  (:documentation "Sign."))

(defmethod op-sign ((ctx context) plain sig &optional (mode :none))
  (with-gpgme-data (in plain)
    (with-gpgme-data (out sig)
      (c-gpgme-op-sign ctx in out mode)
      (c-gpgme-op-sign-result ctx))))

;;; Verify.

(defgeneric op-verify (ctx sig text &key detached)
  (:documentation "Verify."))

(defmethod op-verify ((ctx context) sig text &key detached)
  (with-gpgme-data (in sig)
    (with-gpgme-data (on text)
      (c-gpgme-op-verify ctx in (if detached on nil)
			 (if detached nil on))
      (c-gpgme-op-verify-result ctx))))

;;; Import.

(defgeneric op-import (ctx keydata)
  (:documentation "Import."))

(defmethod op-import ((ctx context) keydata)
  (with-gpgme-data (in keydata)
    (c-gpgme-op-import ctx in)
    (c-gpgme-op-import-result ctx)))

;;; Export.

(defgeneric op-export (ctx pattern keydata)
  (:documentation "Export public key data matching PATTERN to the
                   stream KEYDATA."))

(defmethod op-export ((ctx context) pattern keydata)
  (with-gpgme-data (dh keydata)
    (c-gpgme-op-export ctx pattern 0 dh)))

;;; Key generation.


;;;
;;; Initialization
;;;

(defun check-version (&optional req-version)
  "Check that the GPGME version requirement is satisfied."
  (gpgme-check-version req-version))

(defparameter *version* (check-version)
  "The version number of GPGME used.")

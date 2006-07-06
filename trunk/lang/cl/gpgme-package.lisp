;;;; gpgme-package.lisp

;;; Copyright (C) 2006 g10 Code GmbH
;;;
;;; This file is part of GPGME-CL.
;;;
;;; GPGME-CL is free software; you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published
;;; by the Free Software Foundation; either version 2 of the License,
;;; or (at your option) any later version.
;;;
;;; GPGME-CL is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Lesser General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GPGME; if not, write to the Free Software Foundation,
;;; Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

;;; Conventions:
;;;
;;; gpg-error is used for error handling.
;;;
;;; Standard I/O streams are used for input and output.

(defpackage #:gpgme
  (:use #:common-lisp #:cffi #:gpg-error)

  (:export #:check-version
	   #:*version*
	   #:context
	   #:protocol
	   #:armorp
	   #:textmodep
	   #:+include-certs-default+
	   #:include-certs
	   #:keylist-mode
	   #:signers
	   #:sig-notations
	   #:with-context
	   #:key-data
	   #:get-key
	   #:op-encrypt
	   #:op-decrypt
	   #:op-sign
	   #:op-verify
	   #:op-import
	   #:op-export))

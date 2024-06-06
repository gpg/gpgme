/*
    run-keylist.cpp

    This file is part of GPGME++'s test suite.
    Copyright (c) 2018 Intevation GmbH

    GPGME++ is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

    GPGME++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include "context.h"
#include "key.h"
#include "data.h"
#include "verificationresult.h"

#include <memory>
#include <iostream>

using namespace GpgME;
static int
show_usage (int ex)
{
  fputs ("usage: run-verify [options] [DETACHEDSIGFILE] FILE\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --sender MBOX    use MBOX as sender address\n"
         "  --repeat N       repeat it N times\n"
         "  --list-key       list the signing key afterwards\n"
         , stderr);
  exit (ex);
}

int
main (int argc, char **argv)
{
    int last_argc = -1;
    Protocol protocol = OpenPGP;
    std::string sender;
    int repeats = 1;
    bool verbose = false;
    bool list_key = false;

    if (argc)
    { argc--; argv++; }

    while (argc && last_argc != argc )
    {
        last_argc = argc;
        if (!strcmp (*argv, "--"))
        {
            argc--; argv++;
            break;
        }
        else if (!strcmp (*argv, "--help"))
            show_usage (0);
        else if (!strcmp (*argv, "--verbose"))
        {
            verbose = true;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--list-key"))
        {
            list_key = true;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--openpgp"))
        {
            protocol = OpenPGP;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--cms"))
        {
            protocol = CMS;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--sender"))
        {
            argc--; argv++;
            if (!argc)
                show_usage (1);
            sender = *argv;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--repeat"))
        {
            argc--; argv++;
            if (!argc)
                show_usage (1);
            repeats = atoi (*argv);
            argc--; argv++;
        }
        else if (!strncmp (*argv, "--", 2))
            show_usage (1);
    }

    if (argc < 1 || argc > 2)
        show_usage (1);

    GpgME::initializeLibrary();

    for (int i = 0; i < repeats; i++) {
        std::cout << "Starting run: " << i << std::endl;
        auto ctx = std::unique_ptr<Context> (Context::createForProtocol(protocol));
        if (!ctx) {
            std::cerr << "Failed to get Context";
            return -1;
        }

        std::FILE *fp_sig = fopen (argv[0], "rb");
        if (!fp_sig) {
            std::cerr << "Failed to open sig file";
            exit (1);
        }

        std::FILE *fp_msg = nullptr;
        if (argc > 1)
        {
            fp_msg = fopen (argv[1], "rb");
            if (!fp_msg) {
                std::cerr << "Failed to open msg file";
                exit (1);
            }
        }
        Data dSig(fp_sig);
        Data dMsg;
        bool is_opaque = true;
        if (fp_msg) {
            dMsg = Data(fp_msg);
            is_opaque = false;
        }

        if (!sender.empty()) {
            ctx->setSender(sender.c_str());
        }

        Data output;
        VerificationResult result;
        if (is_opaque) {
            result = ctx->verifyOpaqueSignature(dSig, output);
        } else {
            result = ctx->verifyDetachedSignature(dSig, dMsg);
        }

        Signature sig;
        if (result.numSignatures()) {
            sig = result.signature(0);
        }

        if (list_key && !sig.isNull()) {
            sig.key(true, false);
        }

        if (verbose) {
            std::cout << "Result: " << result << std::endl;
        } else {
            std::cout << "Err:" << result.error() << std::endl;
        }
    }
}

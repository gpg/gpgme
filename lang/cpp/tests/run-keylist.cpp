/*
    run-keylist.cpp

    This file is part of GpgMEpp's test suite.
    Copyright (c) 2018 Intevation GmbH

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

    QGpgME is distributed in the hope that it will be useful,
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "context.h"
#include "key.h"
#include "keylistresult.h"

#include <memory>
#include <sstream>
#include <iostream>

using namespace GpgME;

static int
show_usage (int ex)
{
  fputs ("usage: run-keylist [options] [pattern]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --secret         list only secret keys\n"
         "  --with-secret    list pubkeys with secret info filled\n"
         "  --local          use GPGME_KEYLIST_MODE_LOCAL\n"
         "  --extern         use GPGME_KEYLIST_MODE_EXTERN\n"
         "  --sigs           use GPGME_KEYLIST_MODE_SIGS\n"
         "  --tofu           use GPGME_KEYLIST_MODE_TOFU\n"
         "  --sig-notations  use GPGME_KEYLIST_MODE_SIG_NOTATIONS\n"
         "  --ephemeral      use GPGME_KEYLIST_MODE_EPHEMERAL\n"
         "  --validate       use GPGME_KEYLIST_MODE_VALIDATE\n"
         "  --locate         use GPGME_KEYLIST_MODE_LOCATE\n"
         "  --force-extern   use GPGME_KEYLIST_MODE_FORCE_EXTERN\n"
         "  --locate-external use GPGME_KEYLIST_MODE_LOCATE_EXTERNAL\n"
         , stderr);
  exit (ex);
}

int
main (int argc, char **argv)
{
    int last_argc = -1;
    Protocol protocol = OpenPGP;
    unsigned int mode = 0;
    bool only_secret = false;

    if (argc) {
        argc--; argv++;
    }

    while (argc && last_argc != argc ) {
        last_argc = argc;
        if (!strcmp (*argv, "--")) {
            argc--; argv++;
            break;
        } else if (!strcmp (*argv, "--help")) {
            show_usage (0);
        } else if (!strcmp (*argv, "--openpgp")) {
            protocol = OpenPGP;
            argc--; argv++;
        } else if (!strcmp (*argv, "--cms")) {
            protocol = CMS;
            argc--; argv++;
        } else if (!strcmp (*argv, "--secret")) {
            only_secret = true;
            argc--; argv++;
        } else if (!strcmp (*argv, "--local")) {
            mode |= KeyListMode::Local;
            argc--; argv++;
        } else if (!strcmp (*argv, "--extern")) {
            mode |= KeyListMode::Extern;
            argc--; argv++;
        }else if (!strcmp (*argv, "--tofu")) {
            mode |= KeyListMode::WithTofu;
            argc--; argv++;
        } else if (!strcmp (*argv, "--sigs")) {
            mode |= KeyListMode::Signatures;
            argc--; argv++;
        } else if (!strcmp (*argv, "--sig-notations")) {
            mode |= KeyListMode::SignatureNotations;
            argc--; argv++;
        } else if (!strcmp (*argv, "--ephemeral")) {
            mode |= KeyListMode::Ephemeral;
            argc--; argv++;
        } else if (!strcmp (*argv, "--validate")) {
            mode |= KeyListMode::Validate;
            argc--; argv++;
        } else if (!strcmp (*argv, "--locate")) {
            argc--; argv++;
            mode |= KeyListMode::Locate;
        } else if (!strcmp (*argv, "--with-secret")) {
            argc--; argv++;
            mode |= KeyListMode::WithSecret;
        } else if (!strcmp (*argv, "--force-extern")) {
            argc--; argv++;
            mode |= KeyListMode::ForceExtern;
        } else if (!strcmp (*argv, "--locate-external")) {
            argc--; argv++;
            mode |= KeyListMode::LocateExternal;
        } else if (!strncmp (*argv, "--", 2)) {
            std::cerr << "Error: Unknown option: " << *argv << std::endl;
            show_usage (1);
        }
    }

    if (argc > 1) {
        show_usage (1);
    }

    GpgME::initializeLibrary();
    auto ctx = std::unique_ptr<Context> (Context::createForProtocol(protocol));
    if (!ctx) {
        std::cerr << "Failed to get Context";
        return -1;
    }
    ctx->setKeyListMode (mode);
    if (ctx->keyListMode() != mode) {
        // unfortunately, Context::setKeyListMode() does not return the error
        // returned by gpgme
        std::cerr << "Failed to set keylist mode. You may have used an invalid combination of options.\n";
        return -1;
    }
    Error err = ctx->startKeyListing (*argv, only_secret);
    if (err) {
        std::cout << "Error: " << err.asString() << "\n";
        return -1;
    }
    GpgME::Key key;
    std::stringstream ss;
    do {
        key = ctx->nextKey(err);
        if (!err)
        {
            ss << key << "\n\n";
        }
    } while (!err && !key.isNull());

    std::cout << ss.str();

    return 0;
}

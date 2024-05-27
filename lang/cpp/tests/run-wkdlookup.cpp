/*
    run-wkdlookup.cpp

    This file is part of GpgMEpp's test suite.
    Copyright (c) 2021 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    GPGME++ is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    GPGME++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with GPGME++; see the file COPYING.LIB.  If not, write to the
    Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#include "context.h"
#include "data.h"
#include "defaultassuantransaction.h"
#include "key.h"

#include <memory>
#include <iostream>
#include <thread>

using namespace GpgME;

static int
show_usage (int ex)
{
  fputs ("usage: run-wkdlookup <email address>\n\n"
         , stderr);
  exit (ex);
}

int
main (int argc, char **argv)
{
    int last_argc = -1;

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
        } else if (!strncmp (*argv, "--", 2)) {
            show_usage (1);
        }
    }

    if (argc != 1) {
        show_usage (1);
    }

    const std::string email{*argv};

    GpgME::initializeLibrary();
    Error err;
    auto ctx = std::unique_ptr<Context>{Context::createForEngine(AssuanEngine, &err)};
    if (!ctx) {
        std::cerr << "Failed to get context (Error: " << err.asString() << ")\n";
        return -1;
    }

    const std::string dirmngrSocket = GpgME::dirInfo("dirmngr-socket");
    if ((err = ctx->setEngineFileName(dirmngrSocket.c_str()))) {
        std::cerr << "Failed to set engine file name (Error: " << err.asString() << ")\n";
        return -1;
    }
    if ((err = ctx->setEngineHomeDirectory(""))) {
        std::cerr << "Failed to set engine home directory (Error: " << err.asString() << ")\n";
        return -1;
    }

    // try to connect to dirmngr
    err = ctx->assuanTransact("GETINFO version");
    if (err && err.code() != GPG_ERR_ASS_CONNECT_FAILED) {
        std::cerr << "Failed to start assuan transaction (Error: " << err.asString() << ")\n";
        return -1;
    }
    if (err.code() == GPG_ERR_ASS_CONNECT_FAILED) {
        std::cerr << "Starting dirmngr ...\n";
        auto spawnCtx = std::unique_ptr<Context>{Context::createForEngine(SpawnEngine, &err)};
        if (!spawnCtx) {
            std::cerr << "Failed to get context for spawn engine (Error: " << err.asString() << ")\n";
            return -1;
        }

        const auto gpgconfProgram = GpgME::dirInfo("gpgconf-name");
        // replace backslashes with forward slashes in homedir to work around bug T6833
        std::string homedir{GpgME::dirInfo("homedir")};
        std::replace(homedir.begin(), homedir.end(), '\\', '/');
        const char *argv[] = {
            gpgconfProgram,
            "--homedir",
            homedir.c_str(),
            "--launch",
            "dirmngr",
            NULL
        };
        auto ignoreIO = Data{Data::null};
        err = spawnCtx->spawn(gpgconfProgram, argv,
                              ignoreIO, ignoreIO, ignoreIO,
                              Context::SpawnDetached);
        if (err) {
            std::cerr << "Failed to start dirmngr (Error: " << err.asString() << ")\n";
            return -1;
        }

        // wait for socket to become available
        int cnt = 0;
        do {
            ++cnt;
            std::cerr << "Waiting for dirmngr to start ...\n";
            std::this_thread::sleep_for(std::chrono::milliseconds{250 * cnt});
            err = ctx->assuanTransact("GETINFO version");
        } while (err.code() == GPG_ERR_ASS_CONNECT_FAILED && cnt < 5);
    }

    const auto cmd = std::string{"WKD_GET "} + email;
    err = ctx->assuanTransact(cmd.c_str());
    if (err && err.code() != GPG_ERR_NO_NAME && err.code() != GPG_ERR_NO_DATA) {
        std::cerr << "Error: WKD_GET returned " << err.asString() << "\n";
        return -1;
    }

    const auto transaction = std::unique_ptr<DefaultAssuanTransaction>(dynamic_cast<DefaultAssuanTransaction*>(ctx->takeLastAssuanTransaction().release()));
    const auto source = transaction->firstStatusLine("SOURCE");
    const auto rawData = transaction->data();
    if (rawData.size() == 0) {
        std::cout << "No key found for " << email << "\n";
    } else {
        const auto data = GpgME::Data{rawData.c_str(), rawData.size()};
        const auto keys = data.toKeys(GpgME::OpenPGP);
        for (const auto &key : keys) {
            std::cout << "Found key for " << email << " at " << source << ":\n" << key << "\n";
        }
    }

    return 0;
}

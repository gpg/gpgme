#include "qgpgme_debug.h"


#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
Q_LOGGING_CATEGORY(QGPGME_LOG, "gpg.qgpgme", QtWarningMsg)
Q_LOGGING_CATEGORY(QGPGME_CONFIG_LOADING_LOG, "gpg.qgpgme.config_loading", QtInfoMsg)
#else
Q_LOGGING_CATEGORY(QGPGME_LOG, "gpg.qgpgme")
Q_LOGGING_CATEGORY(QGPGME_CONFIG_LOADING_LOG, "gpg.qgpgme.config_loading")
#endif

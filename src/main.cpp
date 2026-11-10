#include <QApplication>
#include <QEventLoop>
#include <QMessageBox>
#include <QObject>
#include <QStandardPaths>

#include "AuthDialogs.h"
#include "MainWindow.h"
#include "Theme.h"
#include "Vault.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Secure Space"));
    app.setQuitOnLastWindowClosed(false);
    app.setWindowIcon(Theme::appIcon());
    app.setStyleSheet(Theme::styleSheet());

    if (!Vault::initCrypto()) {
        QMessageBox::critical(nullptr, QStringLiteral("Secure Space"),
                              QObject::tr("No se pudo inicializar la criptografía."));
        return 1;
    }

    // Carpeta de la bóveda: oculta, con archivos de nombre aleatorio. SS_VAULT_DIR permite moverla (p. ej. a un USB).
    QString dir = qEnvironmentVariable("SS_VAULT_DIR");
    if (dir.isEmpty())
        dir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/.sscache");

    Vault vault(dir);
    for (;;) {
        if (!vault.exists()) {
            SetupDialog setup(vault);  // primer inicio (o tras una destrucción)
            if (setup.exec() != QDialog::Accepted) return 0;
        } else {
            LoginDialog login(vault);
            if (login.exec() != QDialog::Accepted) {
                if (login.wasDestroyed()) continue;  // volver al estado inicial
                return 0;
            }
        }

        app.setStyleSheet(Theme::styleSheet(vault.settings().uiFontPx));
        MainWindow window(vault);
        QEventLoop loop;
        QObject::connect(&window, &MainWindow::finished, &loop, &QEventLoop::quit);
        window.show();
        loop.exec();
        if (window.result() == MainWindow::Result::Quit) return 0;
        // Locked -> pantalla de acceso; Destroyed -> pantalla de primer inicio
    }
}

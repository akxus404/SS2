#pragma once

#include <QByteArray>
#include <QDialog>
#include <QLineEdit>
#include <QString>

#include "Vault.h"

class QCheckBox;
class QLabel;
class QProgressBar;
class QPushButton;
class QTimer;

// Contraseña -> bytes UTF-8 normalizados (NFC) para que el mismo texto dé siempre la misma clave.
QByteArray passwordBytes(const QString& text);
void wipeBytes(QByteArray& b);

// Barra + etiqueta: Débil / Intermedia / Segura / Súper segura
class StrengthMeter : public QWidget {
    Q_OBJECT
public:
    explicit StrengthMeter(QWidget* parent = nullptr);
    void setPassword(const QString& pw);

private:
    QProgressBar* bar_;
    QLabel* label_;
};

// Contraseña + confirmación + medidor.
class NewPasswordForm : public QWidget {
    Q_OBJECT
public:
    static constexpr int kMinLength = 8;
    explicit NewPasswordForm(QWidget* parent = nullptr);
    QByteArray password() const { return passwordBytes(pw_->text()); }
    bool isValid() const { return valid_; }
    void clear();

signals:
    void validityChanged(bool valid);

private:
    void refresh();
    QLineEdit* pw_;
    QLineEdit* confirm_;
    QCheckBox* show_;
    StrengthMeter* meter_;
    QLabel* msg_;
    bool valid_ = false;
};

// Primer inicio: el usuario elige la contraseña maestra.
class SetupDialog : public QDialog {
    Q_OBJECT
public:
    explicit SetupDialog(Vault& vault, QWidget* parent = nullptr);

private:
    void submit();
    Vault& vault_;
    NewPasswordForm* form_;
    QCheckBox* ack_;
    QPushButton* ok_;
    QLabel* error_;
};

// Inicio normal: pide la contraseña (con política de intentos y retardo).
class LoginDialog : public QDialog {
    Q_OBJECT
public:
    explicit LoginDialog(Vault& vault, QWidget* parent = nullptr);
    bool wasDestroyed() const { return destroyed_; }

private:
    void submit();
    void refreshInfo();
    void tickDelay();
    Vault& vault_;
    QLineEdit* pw_;
    QPushButton* ok_;
    QLabel* error_;
    QLabel* attempts_;
    QTimer* timer_;
    bool destroyed_ = false;
};

class ChangePasswordDialog : public QDialog {
    Q_OBJECT
public:
    explicit ChangePasswordDialog(Vault& vault, QWidget* parent = nullptr);

private:
    void submit();
    Vault& vault_;
    QLineEdit* current_;
    NewPasswordForm* form_;
    QPushButton* ok_;
    QLabel* error_;
};

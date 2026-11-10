#include "AuthDialogs.h"

#include <QApplication>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

#include "Strength.h"
#include "Theme.h"

QByteArray passwordBytes(const QString& text) {
    return text.normalized(QString::NormalizationForm_C).toUtf8();
}

void wipeBytes(QByteArray& b) {
    if (!b.isEmpty()) sodium_memzero(b.data(), std::size_t(b.size()));
}

namespace {
QLabel* makeLabel(const QString& text, const char* objectName = nullptr, bool wrap = false) {
    auto* l = new QLabel(text);
    if (objectName) l->setObjectName(QString::fromLatin1(objectName));
    l->setWordWrap(wrap);
    return l;
}

QLabel* makeLogoTitle(QVBoxLayout* lay, const QString& title, const QString& subtitle) {
    auto* logo = new LogoWidget(96);
    lay->addWidget(logo, 0, Qt::AlignHCenter);
    auto* t = makeLabel(title, "title");
    t->setAlignment(Qt::AlignHCenter);
    lay->addWidget(t);
    auto* s = makeLabel(subtitle, "subtitle", true);
    s->setAlignment(Qt::AlignHCenter);
    lay->addWidget(s);
    return s;
}

void setupDialogFrame(QDialog* d, const QString& title) {
    d->setWindowTitle(title);
    d->setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    d->setFixedWidth(460);
}

void setBusy(bool on) {
    if (on) {
        QApplication::setOverrideCursor(Qt::WaitCursor);
        QCoreApplication::processEvents();  // repinta antes del cálculo (~1 s)
    } else {
        QApplication::restoreOverrideCursor();
    }
}
}  // namespace

// --- StrengthMeter -------------------------------------------------------------------------------

StrengthMeter::StrengthMeter(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(4);
    bar_ = new QProgressBar;
    bar_->setRange(0, 100);
    bar_->setTextVisible(false);
    bar_->setFixedHeight(8);
    label_ = new QLabel;
    auto* row = new QHBoxLayout;
    row->addWidget(makeLabel(tr("Seguridad de la contraseña"), "hint"));
    row->addStretch();
    row->addWidget(label_);
    lay->addWidget(bar_);
    lay->addLayout(row);
    setPassword(QString());
}

void StrengthMeter::setPassword(const QString& pw) {
    using L = Strength::Level;
    int value = 0;
    QRgb color = Theme::kDim;
    QString text = QStringLiteral("—");
    switch (Strength::classify(pw)) {
        case L::Empty: break;
        case L::Weak: value = 25; color = Theme::kDanger; text = tr("Débil"); break;
        case L::Medium: value = 50; color = Theme::kWarn; text = tr("Intermedia"); break;
        case L::Strong: value = 75; color = Theme::kOk; text = tr("Segura"); break;
        case L::VeryStrong: value = 100; color = Theme::kCyan; text = tr("Súper segura"); break;
    }
    bar_->setValue(value);
    bar_->setStyleSheet(QStringLiteral("QProgressBar { border-radius: 4px; } "
                                       "QProgressBar::chunk { background-color: %1; border-radius: 4px; }")
                            .arg(Theme::hex(color)));
    label_->setText(text);
    label_->setStyleSheet(QStringLiteral("color: %1; font-weight: 600;").arg(Theme::hex(color)));
}

// --- NewPasswordForm -----------------------------------------------------------------------------

NewPasswordForm::NewPasswordForm(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(8);
    pw_ = new QLineEdit;
    pw_->setEchoMode(QLineEdit::Password);
    pw_->setPlaceholderText(tr("Contraseña"));
    confirm_ = new QLineEdit;
    confirm_->setEchoMode(QLineEdit::Password);
    confirm_->setPlaceholderText(tr("Repite la contraseña"));
    show_ = new QCheckBox(tr("Mostrar contraseña"));
    meter_ = new StrengthMeter;
    msg_ = makeLabel(QString(), "error", true);
    lay->addWidget(pw_);
    lay->addWidget(meter_);
    lay->addWidget(confirm_);
    lay->addWidget(show_);
    lay->addWidget(msg_);

    connect(pw_, &QLineEdit::textChanged, this, &NewPasswordForm::refresh);
    connect(confirm_, &QLineEdit::textChanged, this, &NewPasswordForm::refresh);
    connect(show_, &QCheckBox::toggled, this, [this](bool on) {
        const auto mode = on ? QLineEdit::Normal : QLineEdit::Password;
        pw_->setEchoMode(mode);
        confirm_->setEchoMode(mode);
    });
}

void NewPasswordForm::refresh() {
    const QString a = pw_->text();
    const QString b = confirm_->text();
    meter_->setPassword(a);
    QString m;
    const bool longEnough = a.size() >= kMinLength;
    if (!a.isEmpty() && !longEnough)
        m = tr("Usa al menos %1 caracteres.").arg(kMinLength);
    else if (!b.isEmpty() && a != b)
        m = tr("Las contraseñas no coinciden.");
    msg_->setText(m);
    const bool ok = longEnough && a == b;
    if (ok != valid_) {
        valid_ = ok;
        emit validityChanged(ok);
    }
}

void NewPasswordForm::clear() {
    pw_->clear();
    confirm_->clear();
}

// --- SetupDialog ---------------------------------------------------------------------------------

SetupDialog::SetupDialog(Vault& vault, QWidget* parent) : QDialog(parent), vault_(vault) {
    setupDialogFrame(this, tr("Secure Space — Primer inicio"));
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(32, 28, 32, 24);
    lay->setSpacing(12);
    makeLogoTitle(lay, tr("Bienvenido a Secure Space"),
                  tr("Elige la contraseña maestra de tu bóveda. Te la pediremos cada vez que abras el programa."));
    lay->addSpacing(6);

    form_ = new NewPasswordForm;
    lay->addWidget(form_);

    ack_ = new QCheckBox(tr("Entiendo que si olvido esta contraseña nadie podrá recuperar mis archivos."));
    lay->addWidget(ack_);
    error_ = makeLabel(QString(), "error", true);
    lay->addWidget(error_);

    auto* row = new QHBoxLayout;
    auto* quit = new QPushButton(tr("Salir"));
    ok_ = new QPushButton(tr("Crear bóveda"));
    ok_->setObjectName(QStringLiteral("primary"));
    ok_->setDefault(true);
    ok_->setEnabled(false);
    row->addWidget(quit);
    row->addStretch();
    row->addWidget(ok_);
    lay->addLayout(row);

    auto update = [this] { ok_->setEnabled(form_->isValid() && ack_->isChecked()); };
    connect(form_, &NewPasswordForm::validityChanged, this, update);
    connect(ack_, &QCheckBox::toggled, this, update);
    connect(quit, &QPushButton::clicked, this, &QDialog::reject);
    connect(ok_, &QPushButton::clicked, this, &SetupDialog::submit);
}

void SetupDialog::submit() {
    QByteArray pw = form_->password();
    ok_->setEnabled(false);
    ok_->setText(tr("Generando claves…"));
    setBusy(true);
    QString err;
    const bool ok = vault_.create(pw, &err);
    setBusy(false);
    wipeBytes(pw);
    form_->clear();
    if (ok) {
        accept();
        return;
    }
    error_->setText(err);
    ok_->setText(tr("Crear bóveda"));
}

// --- LoginDialog ---------------------------------------------------------------------------------

LoginDialog::LoginDialog(Vault& vault, QWidget* parent) : QDialog(parent), vault_(vault) {
    setupDialogFrame(this, tr("Secure Space"));
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(32, 28, 32, 24);
    lay->setSpacing(12);
    makeLogoTitle(lay, QStringLiteral("Secure Space"), tr("Introduce tu contraseña para abrir la bóveda."));
    lay->addSpacing(6);

    pw_ = new QLineEdit;
    pw_->setEchoMode(QLineEdit::Password);
    pw_->setPlaceholderText(tr("Contraseña"));
    lay->addWidget(pw_);
    error_ = makeLabel(QString(), "error", true);
    attempts_ = makeLabel(QString(), "hint", true);
    lay->addWidget(error_);
    lay->addWidget(attempts_);

    auto* row = new QHBoxLayout;
    auto* quit = new QPushButton(tr("Salir"));
    ok_ = new QPushButton(tr("Desbloquear"));
    ok_->setObjectName(QStringLiteral("primary"));
    ok_->setDefault(true);
    row->addWidget(quit);
    row->addStretch();
    row->addWidget(ok_);
    lay->addLayout(row);

    timer_ = new QTimer(this);
    timer_->setInterval(500);
    connect(timer_, &QTimer::timeout, this, &LoginDialog::tickDelay);
    connect(quit, &QPushButton::clicked, this, &QDialog::reject);
    connect(ok_, &QPushButton::clicked, this, &LoginDialog::submit);
    connect(pw_, &QLineEdit::returnPressed, this, &LoginDialog::submit);

    refreshInfo();
    tickDelay();
    pw_->setFocus();
}

void LoginDialog::refreshInfo() {
    const LockState st = vault_.lockState();
    if (st.lockoutEnabled && st.showRemaining) {
        const int left = std::max(0, st.maxAttempts - st.fails);
        attempts_->setText(left <= 1 ? tr("¡Último intento antes de la destrucción de la bóveda!")
                                     : tr("Intentos restantes: %1").arg(left));
        attempts_->setStyleSheet(left <= 1 ? QStringLiteral("color: %1; font-weight: 600;").arg(Theme::hex(Theme::kDanger))
                                           : QString());
    } else {
        attempts_->clear();
    }
}

void LoginDialog::tickDelay() {
    const int s = vault_.retryDelaySeconds();
    if (s > 0) {
        ok_->setEnabled(false);
        pw_->setEnabled(false);
        error_->setText(tr("Demasiados intentos. Espera %1 s para reintentar.").arg(s));
        if (!timer_->isActive()) timer_->start();
    } else {
        const bool wasLocked = !ok_->isEnabled();
        ok_->setEnabled(true);
        pw_->setEnabled(true);
        timer_->stop();
        if (wasLocked) {
            error_->clear();
            pw_->setFocus();
        }
    }
}

void LoginDialog::submit() {
    if (!ok_->isEnabled() || pw_->text().isEmpty()) return;
    QByteArray pw = passwordBytes(pw_->text());
    pw_->clear();
    ok_->setEnabled(false);
    ok_->setText(tr("Verificando…"));
    setBusy(true);
    QString err;
    const Vault::UnlockResult r = vault_.unlock(pw, &err);
    setBusy(false);
    wipeBytes(pw);
    ok_->setText(tr("Desbloquear"));
    ok_->setEnabled(true);

    switch (r) {
        case Vault::UnlockResult::Ok:
            accept();
            return;
        case Vault::UnlockResult::WrongPassword:
            error_->setText(tr("Contraseña incorrecta."));
            refreshInfo();
            tickDelay();
            pw_->setFocus();
            return;
        case Vault::UnlockResult::Destroyed:
            destroyed_ = true;
            QMessageBox::warning(this, QStringLiteral("Secure Space"),
                                 tr("Se superó el número máximo de intentos.\n\nTodo el contenido de la bóveda fue "
                                    "destruido de forma permanente."));
            reject();
            return;
        case Vault::UnlockResult::Error:
            error_->setText(err);
            return;
    }
}

// --- ChangePasswordDialog ------------------------------------------------------------------------

ChangePasswordDialog::ChangePasswordDialog(Vault& vault, QWidget* parent) : QDialog(parent), vault_(vault) {
    setupDialogFrame(this, tr("Cambiar contraseña"));
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(28, 24, 28, 20);
    lay->setSpacing(12);
    lay->addWidget(makeLabel(tr("Cambiar contraseña maestra"), "title"));
    current_ = new QLineEdit;
    current_->setEchoMode(QLineEdit::Password);
    current_->setPlaceholderText(tr("Contraseña actual"));
    lay->addWidget(current_);
    form_ = new NewPasswordForm;
    lay->addWidget(form_);
    error_ = makeLabel(QString(), "error", true);
    lay->addWidget(error_);

    auto* row = new QHBoxLayout;
    auto* cancel = new QPushButton(tr("Cancelar"));
    ok_ = new QPushButton(tr("Cambiar"));
    ok_->setObjectName(QStringLiteral("primary"));
    ok_->setEnabled(false);
    row->addWidget(cancel);
    row->addStretch();
    row->addWidget(ok_);
    lay->addLayout(row);

    auto update = [this] { ok_->setEnabled(form_->isValid() && !current_->text().isEmpty()); };
    connect(form_, &NewPasswordForm::validityChanged, this, update);
    connect(current_, &QLineEdit::textChanged, this, update);
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
    connect(ok_, &QPushButton::clicked, this, &ChangePasswordDialog::submit);
}

void ChangePasswordDialog::submit() {
    QByteArray cur = passwordBytes(current_->text());
    QByteArray next = form_->password();
    ok_->setEnabled(false);
    setBusy(true);
    QString err;
    const bool ok = vault_.changePassword(cur, next, &err);
    setBusy(false);
    wipeBytes(cur);
    wipeBytes(next);
    if (ok) {
        current_->clear();
        form_->clear();
        accept();
        return;
    }
    error_->setText(err);
    ok_->setEnabled(true);
}

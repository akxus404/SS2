#include "SettingsDialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>

#include "AuthDialogs.h"
#include "Theme.h"

namespace {
QWidget* indented(QWidget* inner) {
    auto* w = new QWidget;
    auto* l = new QHBoxLayout(w);
    l->setContentsMargins(26, 0, 0, 0);
    l->addWidget(inner);
    l->addStretch();
    return w;
}
}  // namespace

SettingsDialog::SettingsDialog(Vault& vault, QWidget* parent) : QDialog(parent), vault_(vault) {
    setWindowTitle(tr("Configuración"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setMinimumWidth(580);
    const VaultSettings& s = vault_.settings();

    auto* tabs = new QTabWidget;

    // ---- Seguridad -------------------------------------------------------------------------
    auto* sec = new QWidget;
    auto* secLay = new QVBoxLayout(sec);
    secLay->setSpacing(14);

    auto* g1 = new QGroupBox(tr("Intentos de acceso"));
    auto* g1l = new QVBoxLayout(g1);
    lockout_ = new QCheckBox(tr("Destruir la bóveda al superar un número de contraseñas incorrectas"));
    lockout_->setChecked(s.lockoutEnabled);
    auto* attRow = new QWidget;
    auto* attLay = new QHBoxLayout(attRow);
    attLay->setContentsMargins(0, 0, 0, 0);
    attLay->addWidget(new QLabel(tr("Intentos permitidos:")));
    attempts_ = new QSpinBox;
    attempts_->setRange(1, 99);
    attempts_->setValue(s.maxAttempts);
    attempts_->setEnabled(s.lockoutEnabled);
    attLay->addWidget(attempts_);
    connect(lockout_, &QCheckBox::toggled, attempts_, &QWidget::setEnabled);
    showRemaining_ = new QCheckBox(tr("Mostrar los intentos restantes en la pantalla de acceso"));
    showRemaining_->setChecked(s.showRemaining);
    delay_ = new QCheckBox(tr("Retardo progresivo entre intentos fallidos (frena los ataques de fuerza bruta)"));
    delay_->setChecked(s.progressiveDelay);
    auto* warn = new QLabel(tr("Al alcanzar el límite se borrarán TODOS los archivos de forma irrecuperable y "
                               "Secure Space volverá a su estado inicial."));
    warn->setWordWrap(true);
    warn->setStyleSheet(QStringLiteral("color: %1;").arg(Theme::hex(Theme::kWarn)));
    g1l->addWidget(lockout_);
    g1l->addWidget(indented(attRow));
    g1l->addWidget(indented(warn));
    g1l->addWidget(showRemaining_);
    g1l->addWidget(delay_);
    secLay->addWidget(g1);

    auto* g2 = new QGroupBox(tr("Borrado seguro"));
    auto* g2l = new QVBoxLayout(g2);
    auto* passRow = new QHBoxLayout;
    passRow->addWidget(new QLabel(tr("Sobrescritura al eliminar:")));
    passes_ = new QComboBox;
    passes_->addItem(tr("1 pasada (rápido)"), 1);
    passes_->addItem(tr("3 pasadas (recomendado)"), 3);
    passes_->addItem(tr("7 pasadas (máximo)"), 7);
    const int pi = passes_->findData(s.shredPasses);
    passes_->setCurrentIndex(pi >= 0 ? pi : 1);
    passRow->addWidget(passes_);
    passRow->addStretch();
    shredOriginal_ = new QCheckBox(tr("Destruir el archivo original tras importarlo (mover en vez de copiar)"));
    shredOriginal_->setChecked(s.shredOriginalOnImport);
    g2l->addLayout(passRow);
    g2l->addWidget(shredOriginal_);
    secLay->addWidget(g2);

    auto* g3 = new QGroupBox(tr("Contraseña maestra"));
    auto* g3l = new QHBoxLayout(g3);
    auto* changePw = new QPushButton(tr("Cambiar contraseña…"));
    g3l->addWidget(changePw);
    g3l->addStretch();
    connect(changePw, &QPushButton::clicked, this, [this] { ChangePasswordDialog(vault_, this).exec(); });
    secLay->addWidget(g3);
    secLay->addStretch();
    tabs->addTab(sec, tr("Seguridad"));

    // ---- Privacidad ------------------------------------------------------------------------
    auto* priv = new QWidget;
    auto* privLay = new QVBoxLayout(priv);
    privLay->setSpacing(14);
    auto* g4 = new QGroupBox(tr("Bloqueo"));
    auto* g4l = new QVBoxLayout(g4);
    autoLock_ = new QCheckBox(tr("Bloquear automáticamente por inactividad"));
    autoLock_->setChecked(s.autoLockEnabled);
    auto* idleRow = new QWidget;
    auto* idleLay = new QHBoxLayout(idleRow);
    idleLay->setContentsMargins(0, 0, 0, 0);
    idleLay->addWidget(new QLabel(tr("Tras")));
    autoLockMin_ = new QSpinBox;
    autoLockMin_->setRange(1, 1440);
    autoLockMin_->setSuffix(tr(" min"));
    autoLockMin_->setValue(s.autoLockMinutes);
    autoLockMin_->setEnabled(s.autoLockEnabled);
    idleLay->addWidget(autoLockMin_);
    connect(autoLock_, &QCheckBox::toggled, autoLockMin_, &QWidget::setEnabled);
    lockMinimize_ = new QCheckBox(tr("Bloquear al minimizar la ventana"));
    lockMinimize_->setChecked(s.lockOnMinimize);
    g4l->addWidget(autoLock_);
    g4l->addWidget(indented(idleRow));
    g4l->addWidget(lockMinimize_);
    privLay->addWidget(g4);

    auto* g5 = new QGroupBox(tr("Pantalla"));
    auto* g5l = new QVBoxLayout(g5);
    capture_ = new QCheckBox(tr("Impedir capturas y grabación de pantalla de la ventana"));
    capture_->setChecked(s.blockScreenCapture);
#ifndef Q_OS_WIN
    capture_->setEnabled(false);
    capture_->setToolTip(tr("Disponible solo en Windows."));
#endif
    g5l->addWidget(capture_);
    privLay->addWidget(g5);
    privLay->addStretch();
    tabs->addTab(priv, tr("Privacidad"));

    // ---- General ---------------------------------------------------------------------------
    auto* gen = new QWidget;
    auto* genLay = new QVBoxLayout(gen);
    genLay->setSpacing(14);
    auto* g6 = new QGroupBox(tr("Interfaz"));
    auto* g6l = new QVBoxLayout(g6);
    confirmDelete_ = new QCheckBox(tr("Pedir confirmación antes de eliminar"));
    confirmDelete_->setChecked(s.confirmDelete);
    auto* sizeRow = new QHBoxLayout;
    sizeRow->addWidget(new QLabel(tr("Tamaño de la interfaz:")));
    uiSize_ = new QComboBox;
    uiSize_->addItem(tr("Compacto"), 12);
    uiSize_->addItem(tr("Normal"), 13);
    uiSize_->addItem(tr("Grande"), 15);
    const int ui = uiSize_->findData(s.uiFontPx);
    uiSize_->setCurrentIndex(ui >= 0 ? ui : 1);
    sizeRow->addWidget(uiSize_);
    sizeRow->addStretch();
    g6l->addWidget(confirmDelete_);
    g6l->addLayout(sizeRow);
    genLay->addWidget(g6);

    auto* about = new QLabel(tr("Secure Space 0.1\nCifrado: Argon2id + XChaCha20-Poly1305 (libsodium)"));
    about->setObjectName(QStringLiteral("hint"));
    genLay->addWidget(about);
    genLay->addStretch();
    tabs->addTab(gen, tr("General"));

    // ---- Botones ---------------------------------------------------------------------------
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Guardar"));
    buttons->button(QDialogButtonBox::Ok)->setObjectName(QStringLiteral("primary"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancelar"));
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(20, 18, 20, 16);
    root->addWidget(tabs);
    root->addWidget(buttons);
}

void SettingsDialog::accept() {
    if (lockout_->isChecked() && !vault_.settings().lockoutEnabled) {
        const auto r = QMessageBox::warning(
            this, tr("Destrucción automática"),
            tr("Vas a activar la destrucción automática.\n\nTras %1 contraseña(s) incorrecta(s) se borrará todo "
               "de forma irrecuperable.\n\n¿Activarla?")
                .arg(attempts_->value()),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes) return;
    }
    VaultSettings& s = vault_.settings();
    s.lockoutEnabled = lockout_->isChecked();
    s.maxAttempts = attempts_->value();
    s.showRemaining = showRemaining_->isChecked();
    s.progressiveDelay = delay_->isChecked();
    s.shredPasses = passes_->currentData().toInt();
    s.shredOriginalOnImport = shredOriginal_->isChecked();
    s.autoLockEnabled = autoLock_->isChecked();
    s.autoLockMinutes = autoLockMin_->value();
    s.lockOnMinimize = lockMinimize_->isChecked();
    s.blockScreenCapture = capture_->isChecked();
    s.confirmDelete = confirmDelete_->isChecked();
    s.uiFontPx = uiSize_->currentData().toInt();
    if (!vault_.saveSettings()) {
        QMessageBox::critical(this, tr("Configuración"), tr("No se pudieron guardar los ajustes."));
        return;
    }
    QDialog::accept();
}

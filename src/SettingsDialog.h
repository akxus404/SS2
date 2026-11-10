#pragma once

#include <QDialog>

#include "Vault.h"

class QCheckBox;
class QComboBox;
class QSpinBox;

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(Vault& vault, QWidget* parent = nullptr);

protected:
    void accept() override;

private:
    Vault& vault_;
    // Seguridad
    QCheckBox* lockout_;
    QSpinBox* attempts_;
    QCheckBox* showRemaining_;
    QCheckBox* delay_;
    QComboBox* passes_;
    QCheckBox* shredOriginal_;
    // Privacidad
    QCheckBox* autoLock_;
    QSpinBox* autoLockMin_;
    QCheckBox* lockMinimize_;
    QCheckBox* capture_;
    // General
    QCheckBox* confirmDelete_;
    QComboBox* uiSize_;
};

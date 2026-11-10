#include "MainWindow.h"

#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QEventLoop>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QShortcut>
#include <QStatusBar>
#include <QStyle>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

#include "SettingsDialog.h"
#include "Theme.h"

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
#endif

namespace {
constexpr int kIdRole = Qt::UserRole;
constexpr int kFolderRole = Qt::UserRole + 1;
}  // namespace

MainWindow::MainWindow(Vault& vault, QWidget* parent) : QMainWindow(parent), vault_(vault) {
    setWindowTitle(QStringLiteral("Secure Space"));
    resize(1000, 650);
    setAcceptDrops(true);

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(20, 16, 20, 12);
    root->setSpacing(12);

    // Cabecera: logo, título y acciones globales
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(new LogoWidget(46));
    auto* titles = new QVBoxLayout;
    titles->setSpacing(0);
    auto* title = new QLabel(QStringLiteral("Secure Space"));
    title->setObjectName(QStringLiteral("title"));
    pathLabel_ = new QLabel;
    pathLabel_->setObjectName(QStringLiteral("hint"));
    titles->addWidget(title);
    titles->addWidget(pathLabel_);
    head->addLayout(titles);
    head->addStretch();
    auto* lockBtn = new QPushButton(tr("Bloquear"));
    lockBtn->setToolTip(tr("Bloquear la bóveda (Ctrl+L)"));
    auto* settingsBtn = new QPushButton(tr("Configuración"));
    auto* destroyBtn = new QPushButton(tr("Destruir todo"));
    destroyBtn->setObjectName(QStringLiteral("danger"));
    destroyBtn->setToolTip(tr("Borra de forma permanente e irrecuperable todo el contenido"));
    head->addWidget(lockBtn);
    head->addWidget(settingsBtn);
    head->addWidget(destroyBtn);
    root->addLayout(head);

    // Barra de acciones sobre archivos
    auto* row = new QHBoxLayout;
    row->setSpacing(8);
    upBtn_ = new QPushButton(tr("Subir"));
    auto* importBtn = new QPushButton(tr("Importar archivos"));
    importBtn->setObjectName(QStringLiteral("primary"));
    auto* importDirBtn = new QPushButton(tr("Importar carpeta"));
    auto* folderBtn = new QPushButton(tr("Nueva carpeta"));
    exportBtn_ = new QPushButton(tr("Exportar"));
    renameBtn_ = new QPushButton(tr("Renombrar"));
    deleteBtn_ = new QPushButton(tr("Eliminar"));
    for (QPushButton* b : {upBtn_, importBtn, importDirBtn, folderBtn, exportBtn_, renameBtn_, deleteBtn_}) row->addWidget(b);
    row->addStretch();
    root->addLayout(row);

    // Lista de elementos
    tree_ = new QTreeWidget;
    tree_->setColumnCount(3);
    tree_->setHeaderLabels({tr("Nombre"), tr("Tamaño"), tr("Modificado")});
    tree_->setRootIsDecorated(false);
    tree_->setAlternatingRowColors(true);
    tree_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    tree_->setUniformRowHeights(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree_->header()->setStretchLastSection(false);
    tree_->setColumnWidth(1, 120);
    tree_->setColumnWidth(2, 160);
    root->addWidget(tree_, 1);

    // Barra de estado
    statusLabel_ = new QLabel;
    progress_ = new QProgressBar;
    progress_->setRange(0, 100);
    progress_->setFixedWidth(180);
    progress_->hide();
    statusBar()->addWidget(statusLabel_, 1);
    statusBar()->addPermanentWidget(progress_);

    // Conexiones
    connect(lockBtn, &QPushButton::clicked, this, &MainWindow::lockNow);
    connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::openSettings);
    connect(destroyBtn, &QPushButton::clicked, this, &MainWindow::destroyAll);
    connect(upBtn_, &QPushButton::clicked, this, &MainWindow::goUp);
    connect(importBtn, &QPushButton::clicked, this, &MainWindow::importFiles);
    connect(importDirBtn, &QPushButton::clicked, this, &MainWindow::importFolder);
    connect(folderBtn, &QPushButton::clicked, this, &MainWindow::newFolder);
    connect(exportBtn_, &QPushButton::clicked, this, &MainWindow::exportSelected);
    connect(renameBtn_, &QPushButton::clicked, this, &MainWindow::renameSelected);
    connect(deleteBtn_, &QPushButton::clicked, this, &MainWindow::deleteSelected);
    connect(tree_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem* it, int) { openItem(it); });
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &MainWindow::updateButtons);

    auto bind = [this](const QKeySequence& k, auto slot) {
        connect(new QShortcut(k, this), &QShortcut::activated, this, slot);
    };
    bind(QKeySequence(QStringLiteral("Ctrl+L")), &MainWindow::lockNow);
    bind(QKeySequence(QStringLiteral("Ctrl+I")), &MainWindow::importFiles);
    bind(QKeySequence(QStringLiteral("Ctrl+N")), &MainWindow::newFolder);
    bind(QKeySequence(Qt::Key_F2), &MainWindow::renameSelected);
    bind(QKeySequence(Qt::Key_Delete), &MainWindow::deleteSelected);
    bind(QKeySequence(Qt::Key_Backspace), &MainWindow::goUp);

    idle_.setSingleShot(true);
    connect(&idle_, &QTimer::timeout, this, [this] {
        if (QApplication::activeModalWidget()) {  // no cortar un diálogo en curso: reintentar luego
            idle_.start();
            return;
        }
        lockNow();
    });
    qApp->installEventFilter(this);

    refresh();
    applySettings();
}

MainWindow::~MainWindow() { qApp->removeEventFilter(this); }

// --- lista ---------------------------------------------------------------------------------------

void MainWindow::refresh() {
    tree_->clear();
    const QList<VaultEntry> entries = vault_.children(current_);
    for (const VaultEntry& e : entries) {
        auto* it = new QTreeWidgetItem(tree_);
        it->setText(0, e.name);
        it->setIcon(0, style()->standardIcon(e.isFolder ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
        it->setText(1, e.isFolder ? QString() : QLocale().formattedDataSize(e.size));
        it->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
        it->setText(2, QDateTime::fromSecsSinceEpoch(e.modified).toString(QStringLiteral("dd/MM/yyyy HH:mm")));
        it->setData(0, kIdRole, e.id);
        it->setData(0, kFolderRole, e.isFolder);
    }
    pathLabel_->setText(tr("Bóveda") + vault_.pathOf(current_));
    upBtn_->setEnabled(!current_.isEmpty());
    statusLabel_->setText(entries.isEmpty() ? tr("Vacío — arrastra archivos aquí o pulsa «Importar archivos»")
                                            : tr("%1 elemento(s)").arg(entries.size()));
    updateButtons();
}

void MainWindow::updateButtons() {
    const int n = int(tree_->selectedItems().size());
    exportBtn_->setEnabled(n > 0);
    renameBtn_->setEnabled(n == 1);
    deleteBtn_->setEnabled(n > 0);
}

QStringList MainWindow::selectedIds() const {
    QStringList ids;
    for (QTreeWidgetItem* it : tree_->selectedItems()) ids << it->data(0, kIdRole).toString();
    return ids;
}

void MainWindow::openItem(QTreeWidgetItem* item) {
    if (item && item->data(0, kFolderRole).toBool()) {
        current_ = item->data(0, kIdRole).toString();
        refresh();
    }
}

void MainWindow::goUp() {
    VaultEntry e;
    if (!current_.isEmpty() && vault_.entry(current_, &e)) {
        current_ = e.parentId;
        refresh();
    }
}

// --- operaciones largas --------------------------------------------------------------------------

void MainWindow::beginBusy() {
    busy_ = true;
    idle_.stop();
    progress_->setValue(0);
    progress_->show();
}

void MainWindow::endBusy() {
    busy_ = false;
    progress_->hide();
    if (vault_.settings().autoLockEnabled) idle_.start(vault_.settings().autoLockMinutes * 60 * 1000);
    if (lockPending_) {
        lockPending_ = false;
        lockNow();
    }
}

Vault::Progress MainWindow::progressFn() {
    return [this](qint64 done, qint64 total) {
        progress_->setValue(total > 0 ? int(done * 100 / total) : 100);
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    };
}

// --- importar / exportar -------------------------------------------------------------------------

void MainWindow::importFiles() {
    if (busy_ || done_) return;
    const QStringList files = QFileDialog::getOpenFileNames(this, tr("Importar archivos a la bóveda"));
    if (!files.isEmpty() && !done_) importPaths(files);
}

void MainWindow::importFolder() {
    if (busy_ || done_) return;
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Importar carpeta a la bóveda"));
    if (!dir.isEmpty() && !done_) importPaths({dir});
}

void MainWindow::importPaths(const QStringList& paths) {
    int ok = 0, bad = 0;
    QString err;
    beginBusy();
    for (const QString& p : paths) importOne(p, current_, ok, bad, err);
    endBusy();
    if (done_) return;
    refresh();
    statusLabel_->setText(tr("%1 archivo(s) importado(s)").arg(ok));
    if (bad > 0)
        QMessageBox::warning(this, QStringLiteral("Secure Space"),
                             tr("%1 elemento(s) no se pudieron importar.\n%2").arg(bad).arg(err));
}

void MainWindow::importOne(const QString& path, const QString& parentId, int& ok, int& bad, QString& err) {
    const QFileInfo fi(path);
    const VaultSettings& s = vault_.settings();
    if (fi.isDir()) {
        QString e;
        const QString id = vault_.createFolder(fi.fileName(), parentId, &e);
        if (id.isEmpty()) {
            ++bad;
            err = e;
            return;
        }
        const QFileInfoList kids =
            QDir(path).entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::NoSymLinks);
        for (const QFileInfo& k : kids) importOne(k.absoluteFilePath(), id, ok, bad, err);
        if (s.shredOriginalOnImport) QDir().rmdir(path);  // solo borra si quedó vacía
        return;
    }
    QString e;
    if (vault_.importFile(path, parentId, progressFn(), &e)) {
        ++ok;
        if (s.shredOriginalOnImport) Vault::shredFile(path, s.shredPasses);
    } else {
        ++bad;
        err = e;
    }
}

void MainWindow::exportSelected() {
    const QStringList ids = selectedIds();
    if (ids.isEmpty() || busy_ || done_) return;
    if (!exportWarned_) {
        const auto r = QMessageBox::question(
            this, tr("Exportar"),
            tr("Los archivos exportados quedarán SIN cifrar fuera de la bóveda.\n\n¿Continuar?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes) return;
        exportWarned_ = true;
    }
    const QString dest = QFileDialog::getExistingDirectory(this, tr("Elige la carpeta de destino"));
    if (dest.isEmpty() || done_) return;

    QString err;
    bool ok = true;
    beginBusy();
    for (const QString& id : ids)
        if (!vault_.exportItem(id, dest, progressFn(), &err)) {
            ok = false;
            break;
        }
    endBusy();
    if (done_) return;
    if (ok)
        statusLabel_->setText(tr("Exportación completada."));
    else
        QMessageBox::warning(this, tr("Exportar"), err);
}

// --- carpetas, renombrar, eliminar ---------------------------------------------------------------

void MainWindow::newFolder() {
    if (busy_ || done_) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Nueva carpeta"), tr("Nombre:"), QLineEdit::Normal, QString(), &ok);
    if (!ok || done_) return;
    QString err;
    if (vault_.createFolder(name, current_, &err).isEmpty()) QMessageBox::warning(this, tr("Nueva carpeta"), err);
    refresh();
}

void MainWindow::renameSelected() {
    const QStringList ids = selectedIds();
    VaultEntry e;
    if (ids.size() != 1 || busy_ || done_ || !vault_.entry(ids.first(), &e)) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Renombrar"), tr("Nuevo nombre:"), QLineEdit::Normal, e.name, &ok);
    if (!ok || done_) return;
    QString err;
    if (!vault_.rename(e.id, name, &err)) QMessageBox::warning(this, tr("Renombrar"), err);
    refresh();
}

void MainWindow::deleteSelected() {
    const QStringList ids = selectedIds();
    if (ids.isEmpty() || busy_ || done_) return;
    if (vault_.settings().confirmDelete) {
        const auto r = QMessageBox::warning(
            this, tr("Eliminar"),
            tr("Se destruirán de forma irrecuperable %1 elemento(s).\n\nEsta acción no se puede deshacer.")
                .arg(ids.size()),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes) return;
    }
    QString err;
    bool ok = true;
    beginBusy();
    for (const QString& id : ids)
        if (!vault_.remove(id, progressFn(), &err)) {
            ok = false;
            break;
        }
    endBusy();
    if (done_) return;
    refresh();
    if (!ok) QMessageBox::warning(this, tr("Eliminar"), err);
}

// --- destrucción total ---------------------------------------------------------------------------

void MainWindow::destroyAll() {
    if (busy_ || done_) return;
    bool ok = false;
    const QString typed = QInputDialog::getText(
        this, tr("Destruir todo"),
        tr("Esto borrará de forma PERMANENTE e IRRECUPERABLE todos los archivos de la bóveda y la contraseña. "
           "Secure Space volverá a su estado inicial.\n\nEscribe DESTRUIR para confirmar:"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || typed.trimmed() != QLatin1String("DESTRUIR")) return;

    beginBusy();
    vault_.destroyEverything(progressFn());
    busy_ = false;
    progress_->hide();
    QMessageBox::information(this, QStringLiteral("Secure Space"),
                             tr("La bóveda fue destruida. Secure Space volverá a su estado inicial."));
    finish(Result::Destroyed);
}

// --- ajustes, bloqueo y ventana ------------------------------------------------------------------

void MainWindow::openSettings() {
    if (busy_ || done_) return;
    SettingsDialog dlg(vault_, this);
    if (dlg.exec() == QDialog::Accepted && !done_) applySettings();
}

void MainWindow::applySettings() {
    const VaultSettings& s = vault_.settings();
    idle_.stop();
    if (s.autoLockEnabled) idle_.start(s.autoLockMinutes * 60 * 1000);
    applyCaptureProtection();
    qApp->setStyleSheet(Theme::styleSheet(s.uiFontPx));
}

void MainWindow::applyCaptureProtection() {
#ifdef Q_OS_WIN
    if (!isVisible()) return;
    SetWindowDisplayAffinity(reinterpret_cast<HWND>(winId()),
                             vault_.settings().blockScreenCapture ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
#endif
}

void MainWindow::lockNow() {
    if (done_) return;
    if (busy_) {
        lockPending_ = true;
        return;
    }
    finish(Result::Locked);
}

void MainWindow::finish(Result r) {
    if (done_) return;
    done_ = true;
    result_ = r;
    idle_.stop();
    vault_.lock();
    hide();
    emit finished();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    if (busy_) {
        e->ignore();
        return;
    }
    finish(Result::Quit);
    e->accept();
}

void MainWindow::changeEvent(QEvent* e) {
    QMainWindow::changeEvent(e);
    if (e->type() == QEvent::WindowStateChange && isMinimized() && vault_.settings().lockOnMinimize)
        QTimer::singleShot(0, this, &MainWindow::lockNow);
}

void MainWindow::showEvent(QShowEvent* e) {
    QMainWindow::showEvent(e);
    applyCaptureProtection();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (e->mimeData()->hasUrls() && !busy_) e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* e) {
    QStringList paths;
    for (const QUrl& u : e->mimeData()->urls())
        if (u.isLocalFile()) paths << u.toLocalFile();
    if (!paths.isEmpty() && !busy_ && !done_) importPaths(paths);
}

bool MainWindow::eventFilter(QObject* obj, QEvent* e) {
    switch (e->type()) {  // cualquier actividad reinicia el temporizador de inactividad
        case QEvent::MouseMove:
        case QEvent::MouseButtonPress:
        case QEvent::KeyPress:
        case QEvent::Wheel:
            if (idle_.isActive()) idle_.start();
            break;
        default: break;
    }
    return QMainWindow::eventFilter(obj, e);
}

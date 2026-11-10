#pragma once

#include <QMainWindow>
#include <QStringList>
#include <QTimer>

#include "Vault.h"

class QLabel;
class QProgressBar;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    enum class Result { Quit, Locked, Destroyed };

    explicit MainWindow(Vault& vault, QWidget* parent = nullptr);
    ~MainWindow() override;
    Result result() const { return result_; }

signals:
    void finished();  // la sesión terminó (cerrar, bloquear o destruir)

protected:
    void closeEvent(QCloseEvent* e) override;
    void changeEvent(QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void dragEnterEvent(QDragEnterEvent* e) override;
    void dropEvent(QDropEvent* e) override;
    bool eventFilter(QObject* obj, QEvent* e) override;

private:
    void refresh();
    void updateButtons();
    QStringList selectedIds() const;
    void openItem(QTreeWidgetItem* item);
    void goUp();
    void importFiles();
    void importFolder();
    void importPaths(const QStringList& paths);
    void importOne(const QString& path, const QString& parentId, int& ok, int& bad, QString& err);
    void newFolder();
    void exportSelected();
    void renameSelected();
    void deleteSelected();
    void destroyAll();
    void openSettings();
    void applySettings();
    void applyCaptureProtection();
    void lockNow();
    void finish(Result r);
    void beginBusy();
    void endBusy();
    Vault::Progress progressFn();

    Vault& vault_;
    QTreeWidget* tree_;
    QLabel* pathLabel_;
    QLabel* statusLabel_;
    QProgressBar* progress_;
    QPushButton* upBtn_;
    QPushButton* exportBtn_;
    QPushButton* renameBtn_;
    QPushButton* deleteBtn_;
    QTimer idle_;
    QString current_;  // carpeta actual (id); vacío = raíz
    Result result_ = Result::Quit;
    bool done_ = false;
    bool busy_ = false;
    bool lockPending_ = false;
    bool exportWarned_ = false;
};

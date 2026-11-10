#pragma once

#include <sodium.h>

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <vector>

// Clave de 32 bytes en memoria protegida (sodium_malloc: páginas con guardas, se borra al liberar).
// Requiere haber llamado antes a Vault::initCrypto().
class SecretKey {
public:
    static constexpr std::size_t kSize = 32;
    SecretKey() : p_(static_cast<unsigned char*>(sodium_malloc(kSize))) {
        if (!p_) std::abort();
        sodium_memzero(p_, kSize);
    }
    ~SecretKey() { sodium_free(p_); }
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    unsigned char* data() { return p_; }
    const unsigned char* data() const { return p_; }
    void clear() { sodium_memzero(p_, kSize); }
    void randomize() { randombytes_buf(p_, kSize); }

private:
    unsigned char* p_;
};

// Ajustes del usuario. Se guardan DENTRO del índice cifrado.
struct VaultSettings {
    // Seguridad
    bool lockoutEnabled = false;  // destruir tras N contraseñas incorrectas
    int maxAttempts = 5;
    bool showRemaining = true;    // mostrar intentos restantes en el login
    bool progressiveDelay = true; // retardo creciente entre intentos fallidos
    int shredPasses = 3;          // pasadas de sobrescritura al borrar
    bool shredOriginalOnImport = false;
    // Privacidad
    bool autoLockEnabled = true;
    int autoLockMinutes = 5;
    bool lockOnMinimize = true;
    bool blockScreenCapture = true;  // solo Windows
    // General
    bool confirmDelete = true;
    int uiFontPx = 13;
};

// Estado necesario ANTES de desbloquear (contador de fallos y política). Va en claro en st.bin.
struct LockState {
    int fails = 0;
    qint64 lastFail = 0;
    bool lockoutEnabled = false;
    int maxAttempts = 5;
    bool progressiveDelay = true;
    bool showRemaining = true;
    int shredPasses = 3;
};

struct VaultEntry {  // lo que ve la interfaz (sin claves)
    QString id;
    QString parentId;  // vacío = raíz
    QString name;
    bool isFolder = false;
    qint64 size = 0;
    qint64 modified = 0;  // epoch en segundos
};

struct VaultItem : VaultEntry {
    std::array<unsigned char, 32> key{};  // clave propia de cada archivo
};

class Vault {
public:
    enum class UnlockResult { Ok, WrongPassword, Destroyed, Error };
    using Progress = std::function<void(qint64 done, qint64 total)>;

    explicit Vault(const QString& dir);
    ~Vault();
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    static bool initCrypto();

    bool exists() const;
    bool isUnlocked() const { return unlocked_; }
    LockState lockState() const;
    int retryDelaySeconds() const;  // espera restante antes de poder reintentar

    bool create(const QByteArray& password, QString* error = nullptr);  // deja la bóveda desbloqueada
    UnlockResult unlock(const QByteArray& password, QString* error = nullptr);
    void lock();
    bool changePassword(const QByteArray& current, const QByteArray& next, QString* error = nullptr);
    void destroyEverything(const Progress& progress = {});  // destrucción total: vuelve al estado inicial

    VaultSettings& settings() { return settings_; }
    const VaultSettings& settings() const { return settings_; }
    bool saveSettings();

    // Navegación y operaciones
    QList<VaultEntry> children(const QString& parentId) const;
    bool entry(const QString& id, VaultEntry* out) const;
    QString pathOf(const QString& id) const;

    bool importFile(const QString& srcPath, const QString& parentId, const Progress& progress, QString* error);
    QString createFolder(const QString& name, const QString& parentId, QString* error);
    bool rename(const QString& id, const QString& newName, QString* error);
    bool remove(const QString& id, const Progress& progress, QString* error);
    bool exportItem(const QString& id, const QString& destDir, const Progress& progress, QString* error) const;

    // Borrado seguro de un archivo cualquiera: sobrescribe con aleatorios, trunca, renombra y elimina.
    static void shredFile(const QString& path, int passes);

private:
    enum class HeaderResult { Ok, Wrong, Bad };

    QString pathIn(const QString& name) const;
    QString headerPath() const;
    QString indexPath() const;
    QString statePath() const;
    QString blobPath(const QString& id) const;

    LockState readState() const;
    void writeState(const LockState& s) const;
    LockState stateFromSettings() const;

    HeaderResult openHeader(const QByteArray& pw, SecretKey& vmkOut, QString* err) const;
    bool writeHeader(const unsigned char* salt, quint64 ops, quint64 mem, const SecretKey& kek);
    void deriveIndexKey();
    bool loadIndex();
    bool saveIndex();
    bool replaceFile(const QString& path, const QByteArray& data);
    void recoverTmp(const QString& path) const;
    void purgeOrphans();
    int passes() const;
    int indexOf(const QString& id) const;
    void collect(const QString& id, QStringList& out) const;
    QString uniqueName(const QString& parentId, const QString& name, const QString& ignoreId) const;
    static bool validName(const QString& name);

    QString dir_;
    bool unlocked_ = false;
    SecretKey vmk_;    // clave maestra de la bóveda (aleatoria, protegida por la contraseña)
    SecretKey ixKey_;  // clave del índice, derivada de vmk_
    VaultSettings settings_;
    std::vector<VaultItem> items_;
};

#include "Vault.h"

#include <QDataStream>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QRegularExpression>
#include <QSet>
#include <algorithm>
#include <cstring>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

constexpr char kMagic[4] = {'S', 'S', 'V', '1'};
constexpr qint64 kChunk = 1 << 20;  // 1 MiB por bloque cifrado
constexpr int kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr int kTag = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr int kSalt = crypto_pwhash_SALTBYTES;
constexpr int kKey = 32;
constexpr int kHeadLen = 4 + 8 + 8 + kSalt;  // magic + ops + mem + salt (autenticado como AD)
constexpr quint64 kOps = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr quint64 kMem = crypto_pwhash_MEMLIMIT_MODERATE;
constexpr char kIndexCtx[] = "SSINDEX1";  // 8 bytes exactos

const QString kHeaderFile = QStringLiteral("cfg.bin");
const QString kIndexFile = QStringLiteral("ix.bin");
const QString kStateFile = QStringLiteral("st.bin");
const QString kTmpSuffix = QStringLiteral(".tmp");

bool fail(QString* e, const QString& msg) {
    if (e) *e = msg;
    return false;
}

const unsigned char* u8(const QByteArray& b) { return reinterpret_cast<const unsigned char*>(b.constData()); }
unsigned char* u8(QByteArray& b) { return reinterpret_cast<unsigned char*>(b.data()); }

struct Wipe {  // borra un buffer al salir del ámbito
    void* p;
    std::size_t n;
    ~Wipe() { sodium_memzero(p, n); }
};

void syncFile(QFile& f) {
    f.flush();
#ifdef Q_OS_WIN
    FlushFileBuffers(reinterpret_cast<HANDLE>(_get_osfhandle(f.handle())));
#else
    (void)::fsync(f.handle());
#endif
}

QString randomId() {
    unsigned char b[16];
    randombytes_buf(b, sizeof b);
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(b), sizeof b).toHex());
}

QJsonObject toJson(const VaultSettings& s) {
    QJsonObject o;
    o["lockout"] = s.lockoutEnabled;
    o["max"] = s.maxAttempts;
    o["remaining"] = s.showRemaining;
    o["delay"] = s.progressiveDelay;
    o["passes"] = s.shredPasses;
    o["shredOrig"] = s.shredOriginalOnImport;
    o["autoLock"] = s.autoLockEnabled;
    o["autoLockMin"] = s.autoLockMinutes;
    o["lockMin"] = s.lockOnMinimize;
    o["capture"] = s.blockScreenCapture;
    o["confirmDel"] = s.confirmDelete;
    o["font"] = s.uiFontPx;
    return o;
}

VaultSettings fromJson(const QJsonObject& o) {
    VaultSettings s;
    s.lockoutEnabled = o.value("lockout").toBool(s.lockoutEnabled);
    s.maxAttempts = std::clamp(o.value("max").toInt(s.maxAttempts), 1, 99);
    s.showRemaining = o.value("remaining").toBool(s.showRemaining);
    s.progressiveDelay = o.value("delay").toBool(s.progressiveDelay);
    s.shredPasses = std::clamp(o.value("passes").toInt(s.shredPasses), 1, 35);
    s.shredOriginalOnImport = o.value("shredOrig").toBool(s.shredOriginalOnImport);
    s.autoLockEnabled = o.value("autoLock").toBool(s.autoLockEnabled);
    s.autoLockMinutes = std::clamp(o.value("autoLockMin").toInt(s.autoLockMinutes), 1, 1440);
    s.lockOnMinimize = o.value("lockMin").toBool(s.lockOnMinimize);
    s.blockScreenCapture = o.value("capture").toBool(s.blockScreenCapture);
    s.confirmDelete = o.value("confirmDel").toBool(s.confirmDelete);
    s.uiFontPx = std::clamp(o.value("font").toInt(s.uiFontPx), 10, 20);
    return s;
}

// Cifrado de archivos en flujo: bloques de 1 MiB autenticados (secretstream XChaCha20-Poly1305).
bool encryptStream(QIODevice& in, QIODevice& out, const unsigned char* key, qint64 total,
                   const Vault::Progress& prog) {
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, key) != 0) return false;
    if (out.write(reinterpret_cast<const char*>(hdr), qint64(sizeof hdr)) != qint64(sizeof hdr)) return false;

    std::vector<unsigned char> plain(std::size_t(kChunk));
    std::vector<unsigned char> ct(std::size_t(kChunk) + crypto_secretstream_xchacha20poly1305_ABYTES);
    Wipe w1{plain.data(), plain.size()};
    Wipe w2{&st, sizeof st};

    qint64 done = 0;
    for (;;) {
        const qint64 n = in.read(reinterpret_cast<char*>(plain.data()), kChunk);
        if (n < 0) return false;
        const bool last = in.atEnd();
        unsigned long long clen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st, ct.data(), &clen, plain.data(), static_cast<unsigned long long>(n), nullptr, 0,
            last ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        if (out.write(reinterpret_cast<const char*>(ct.data()), qint64(clen)) != qint64(clen)) return false;
        done += n;
        if (prog) prog(done, total);
        if (last) break;
    }
    return true;
}

bool decryptStream(QIODevice& in, QIODevice& out, const unsigned char* key, qint64 total,
                   const Vault::Progress& prog) {
    unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (in.read(reinterpret_cast<char*>(hdr), qint64(sizeof hdr)) != qint64(sizeof hdr)) return false;
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, hdr, key) != 0) return false;

    constexpr qint64 kAbytes = crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<unsigned char> ct(std::size_t(kChunk + kAbytes));
    std::vector<unsigned char> plain(std::size_t(kChunk));
    Wipe w1{plain.data(), plain.size()};
    Wipe w2{&st, sizeof st};

    qint64 done = 0;
    for (;;) {
        const qint64 n = in.read(reinterpret_cast<char*>(ct.data()), kChunk + kAbytes);
        if (n < kAbytes) return false;  // truncado o error de lectura
        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, plain.data(), &plen, &tag, ct.data(),
                                                        static_cast<unsigned long long>(n), nullptr, 0) != 0)
            return false;  // manipulado o clave incorrecta
        if (out.write(reinterpret_cast<const char*>(plain.data()), qint64(plen)) != qint64(plen)) return false;
        done += qint64(plen);
        if (prog) prog(done, total);
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) return in.atEnd();
    }
}

QString safeFileName(QString n) {
    for (QChar& c : n) {
        if (c == QLatin1Char('/') || c == QLatin1Char('\\') || c == QLatin1Char(':') || c == QLatin1Char('*') ||
            c == QLatin1Char('?') || c == QLatin1Char('"') || c == QLatin1Char('<') || c == QLatin1Char('>') ||
            c == QLatin1Char('|') || c.unicode() < 32)
            c = QLatin1Char('_');
    }
    return n.isEmpty() ? QStringLiteral("_") : n;
}

QString uniquePath(const QString& path) {
    if (!QFileInfo::exists(path)) return path;
    const QFileInfo fi(path);
    const QString suf = fi.suffix().isEmpty() ? QString() : QStringLiteral(".") + fi.suffix();
    for (int i = 2;; ++i) {
        const QString p = fi.dir().filePath(QStringLiteral("%1 (%2)%3").arg(fi.completeBaseName()).arg(i).arg(suf));
        if (!QFileInfo::exists(p)) return p;
    }
}

}  // namespace

// ---------------------------------------------------------------------------------------------

Vault::Vault(const QString& dir) : dir_(dir) {}
Vault::~Vault() { lock(); }

bool Vault::initCrypto() { return sodium_init() >= 0; }

QString Vault::pathIn(const QString& name) const { return QDir(dir_).filePath(name); }
QString Vault::headerPath() const { return pathIn(kHeaderFile); }
QString Vault::indexPath() const { return pathIn(kIndexFile); }
QString Vault::statePath() const { return pathIn(kStateFile); }
QString Vault::blobPath(const QString& id) const { return pathIn(id); }

bool Vault::exists() const {
    return QFile::exists(headerPath()) || QFile::exists(headerPath() + kTmpSuffix);
}

int Vault::passes() const { return unlocked_ ? settings_.shredPasses : readState().shredPasses; }

// --- estado previo al desbloqueo ---------------------------------------------------------------

LockState Vault::readState() const {
    LockState s;
    QFile f(statePath());
    if (!f.open(QIODevice::ReadOnly)) return s;
    const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
    s.fails = std::max(0, o.value("f").toInt(0));
    s.lastFail = o.value("t").toInteger(0);
    s.lockoutEnabled = o.value("e").toBool(false);
    s.maxAttempts = std::clamp(o.value("m").toInt(5), 1, 99);
    s.progressiveDelay = o.value("d").toBool(true);
    s.showRemaining = o.value("r").toBool(true);
    s.shredPasses = std::clamp(o.value("p").toInt(3), 1, 35);
    return s;
}

void Vault::writeState(const LockState& s) const {
    QJsonObject o;
    o["f"] = s.fails;
    o["t"] = s.lastFail;
    o["e"] = s.lockoutEnabled;
    o["m"] = s.maxAttempts;
    o["d"] = s.progressiveDelay;
    o["r"] = s.showRemaining;
    o["p"] = s.shredPasses;
    QDir().mkpath(dir_);
    QFile f(statePath());
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(o).toJson(QJsonDocument::Compact));
        syncFile(f);
    }
}

LockState Vault::stateFromSettings() const {
    LockState s;
    s.lockoutEnabled = settings_.lockoutEnabled;
    s.maxAttempts = settings_.maxAttempts;
    s.progressiveDelay = settings_.progressiveDelay;
    s.showRemaining = settings_.showRemaining;
    s.shredPasses = settings_.shredPasses;
    return s;
}

LockState Vault::lockState() const { return readState(); }

int Vault::retryDelaySeconds() const {
    const LockState st = readState();
    if (!st.progressiveDelay || st.fails < 3) return 0;
    const int delay = std::min(30, 1 << std::min(st.fails - 2, 5));  // 2, 4, 8, 16, 30 s
    const qint64 elapsed = QDateTime::currentSecsSinceEpoch() - st.lastFail;
    return int(std::max<qint64>(0, delay - elapsed));
}

// --- cabecera (contraseña -> clave maestra) ----------------------------------------------------

Vault::HeaderResult Vault::openHeader(const QByteArray& pw, SecretKey& vmkOut, QString* err) const {
    QFile f(headerPath());
    if (!f.open(QIODevice::ReadOnly)) {
        if (err) *err = QObject::tr("No se pudo leer la bóveda.");
        return HeaderResult::Bad;
    }
    const QByteArray raw = f.readAll();
    if (raw.size() != kHeadLen + kNonce + kKey + kTag || std::memcmp(raw.constData(), kMagic, 4) != 0) {
        if (err) *err = QObject::tr("La cabecera de la bóveda está dañada.");
        return HeaderResult::Bad;
    }
    QDataStream ds(raw);
    ds.skipRawData(4);
    quint64 ops = 0, mem = 0;
    ds >> ops >> mem;
    if (ops < 1 || ops > 64 || mem < (8ull << 20) || mem > (4ull << 30)) {
        if (err) *err = QObject::tr("Parámetros de cifrado no válidos.");
        return HeaderResult::Bad;
    }
    const unsigned char* base = u8(raw);
    SecretKey kek;
    if (crypto_pwhash(kek.data(), kKey, pw.constData(), static_cast<unsigned long long>(pw.size()),
                      base + (kHeadLen - kSalt), ops, static_cast<std::size_t>(mem),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        if (err) *err = QObject::tr("No hay memoria suficiente para derivar la clave.");
        return HeaderResult::Bad;
    }
    const unsigned char* nonce = base + kHeadLen;
    const unsigned char* ct = nonce + kNonce;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(vmkOut.data(), nullptr, nullptr, ct, kKey + kTag, base,
                                                   kHeadLen, nonce, kek.data()) != 0) {
        vmkOut.clear();
        return HeaderResult::Wrong;
    }
    return HeaderResult::Ok;
}

bool Vault::writeHeader(const unsigned char* salt, quint64 ops, quint64 mem, const SecretKey& kek) {
    QByteArray blob;
    {
        QDataStream ds(&blob, QIODevice::WriteOnly);
        ds.writeRawData(kMagic, 4);
        ds << ops << mem;
        ds.writeRawData(reinterpret_cast<const char*>(salt), kSalt);
    }
    unsigned char nonce[kNonce];
    randombytes_buf(nonce, sizeof nonce);
    QByteArray wrapped(kKey + kTag, '\0');
    crypto_aead_xchacha20poly1305_ietf_encrypt(u8(wrapped), nullptr, vmk_.data(), kKey, u8(blob),
                                               static_cast<unsigned long long>(blob.size()), nullptr, nonce,
                                               kek.data());
    blob.append(reinterpret_cast<const char*>(nonce), kNonce);
    blob.append(wrapped);
    return replaceFile(headerPath(), blob);
}

// --- índice cifrado ----------------------------------------------------------------------------

void Vault::deriveIndexKey() { crypto_kdf_derive_from_key(ixKey_.data(), kKey, 1, kIndexCtx, vmk_.data()); }

bool Vault::loadIndex() {
    QFile f(indexPath());
    if (!f.open(QIODevice::ReadOnly)) return false;
    const QByteArray raw = f.readAll();
    if (raw.size() < kNonce + kTag) return false;
    QByteArray plain(raw.size() - kNonce - kTag, '\0');
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(u8(plain), &plen, nullptr, u8(raw) + kNonce,
                                                   static_cast<unsigned long long>(raw.size() - kNonce), nullptr, 0,
                                                   u8(raw), ixKey_.data()) != 0)
        return false;
    plain.truncate(qsizetype(plen));
    const QJsonObject root = QJsonDocument::fromJson(plain).object();
    sodium_memzero(plain.data(), std::size_t(plain.size()));
    if (root.value("v").toInt() != 1) return false;

    settings_ = fromJson(root.value("settings").toObject());
    items_.clear();
    const QJsonArray arr = root.value("items").toArray();
    for (const QJsonValue& v : arr) {
        const QJsonObject o = v.toObject();
        VaultItem it;
        it.id = o.value("i").toString();
        it.parentId = o.value("p").toString();
        it.name = o.value("n").toString();
        it.isFolder = o.value("d").toBool();
        it.size = o.value("s").toInteger();
        it.modified = o.value("m").toInteger();
        if (it.id.isEmpty()) return false;
        if (!it.isFolder) {
            const QByteArray k = QByteArray::fromBase64(o.value("k").toString().toLatin1());
            if (k.size() != kKey) return false;
            std::memcpy(it.key.data(), k.constData(), kKey);
        }
        items_.push_back(it);
    }
    return true;
}

bool Vault::saveIndex() {
    QJsonArray arr;
    for (const VaultItem& it : items_) {
        QJsonObject o;
        o["i"] = it.id;
        o["p"] = it.parentId;
        o["n"] = it.name;
        o["d"] = it.isFolder;
        o["s"] = it.size;
        o["m"] = it.modified;
        if (!it.isFolder)
            o["k"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(it.key.data()), kKey).toBase64());
        arr.append(o);
    }
    QJsonObject root;
    root["v"] = 1;
    root["settings"] = toJson(settings_);
    root["items"] = arr;

    QByteArray plain = QJsonDocument(root).toJson(QJsonDocument::Compact);
    plain.append(QByteArray((4096 - plain.size() % 4096) % 4096, ' '));  // relleno: oculta la cantidad de archivos

    unsigned char nonce[kNonce];
    randombytes_buf(nonce, sizeof nonce);
    QByteArray out(kNonce + plain.size() + kTag, '\0');
    std::memcpy(out.data(), nonce, kNonce);
    crypto_aead_xchacha20poly1305_ietf_encrypt(u8(out) + kNonce, nullptr, u8(plain),
                                               static_cast<unsigned long long>(plain.size()), nullptr, 0, nullptr,
                                               nonce, ixKey_.data());
    sodium_memzero(plain.data(), std::size_t(plain.size()));
    return replaceFile(indexPath(), out);
}

// Escritura "atómica": se escribe a .tmp, se destruye el antiguo y se renombra el nuevo.
bool Vault::replaceFile(const QString& path, const QByteArray& data) {
    const QString tmp = path + kTmpSuffix;
    {
        QFile f(tmp);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        if (f.write(data) != data.size()) return false;
        syncFile(f);
    }
    if (QFile::exists(path)) shredFile(path, passes());
    return QFile::rename(tmp, path);
}

void Vault::recoverTmp(const QString& path) const {
    if (!QFile::exists(path) && QFile::exists(path + kTmpSuffix)) QFile::rename(path + kTmpSuffix, path);
}

void Vault::purgeOrphans() {  // blobs que ya no figuran en el índice (p. ej. tras un corte de energía)
    static const QRegularExpression re(QStringLiteral("^[0-9a-f]{32}$"));
    QSet<QString> known;
    for (const VaultItem& it : items_) known.insert(it.id);
    const QStringList names = QDir(dir_).entryList(QDir::Files | QDir::Hidden);
    for (const QString& n : names)
        if (re.match(n).hasMatch() && !known.contains(n)) shredFile(pathIn(n), settings_.shredPasses);
}

// --- ciclo de vida -----------------------------------------------------------------------------

bool Vault::create(const QByteArray& pw, QString* err) {
    if (exists()) return fail(err, QObject::tr("Ya existe una bóveda."));
    if (!QDir().mkpath(dir_)) return fail(err, QObject::tr("No se pudo crear el directorio de la bóveda."));
#ifdef Q_OS_WIN
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(dir_).utf16()), FILE_ATTRIBUTE_HIDDEN);
#endif
    unsigned char salt[kSalt];
    randombytes_buf(salt, sizeof salt);
    SecretKey kek;
    if (crypto_pwhash(kek.data(), kKey, pw.constData(), static_cast<unsigned long long>(pw.size()), salt, kOps,
                      static_cast<std::size_t>(kMem), crypto_pwhash_ALG_ARGON2ID13) != 0)
        return fail(err, QObject::tr("No hay memoria suficiente para derivar la clave."));

    vmk_.randomize();
    deriveIndexKey();
    items_.clear();
    settings_ = VaultSettings();
    if (!writeHeader(salt, kOps, kMem, kek) || !saveIndex()) {
        destroyEverything();
        return fail(err, QObject::tr("No se pudo escribir la bóveda en el disco."));
    }
    writeState(stateFromSettings());
    unlocked_ = true;
    return true;
}

Vault::UnlockResult Vault::unlock(const QByteArray& pw, QString* err) {
    if (unlocked_) return UnlockResult::Ok;
    recoverTmp(headerPath());
    recoverTmp(indexPath());
    if (!QFile::exists(headerPath())) {
        if (err) *err = QObject::tr("No existe ninguna bóveda.");
        return UnlockResult::Error;
    }

    // El intento se cuenta ANTES de derivar la clave: si se mata el proceso a mitad, igualmente cuenta.
    const LockState before = readState();
    LockState st = before;
    st.fails += 1;
    st.lastFail = QDateTime::currentSecsSinceEpoch();
    writeState(st);

    QString e;
    const HeaderResult hr = openHeader(pw, vmk_, &e);
    if (hr == HeaderResult::Bad) {
        writeState(before);  // un error técnico no cuenta como intento
        if (err) *err = e;
        return UnlockResult::Error;
    }
    if (hr == HeaderResult::Wrong) {
        if (st.lockoutEnabled && st.fails >= st.maxAttempts) {
            destroyEverything();
            return UnlockResult::Destroyed;
        }
        return UnlockResult::WrongPassword;
    }

    deriveIndexKey();
    if (!loadIndex()) {
        lock();
        writeState(before);
        if (err) *err = QObject::tr("El índice está dañado o fue manipulado.");
        return UnlockResult::Error;
    }
    unlocked_ = true;
    purgeOrphans();
    writeState(stateFromSettings());  // fails = 0
    return UnlockResult::Ok;
}

void Vault::lock() {
    for (VaultItem& it : items_) sodium_memzero(it.key.data(), it.key.size());
    items_.clear();
    items_.shrink_to_fit();
    vmk_.clear();
    ixKey_.clear();
    unlocked_ = false;
}

bool Vault::changePassword(const QByteArray& current, const QByteArray& next, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    SecretKey tmp;
    QString e;
    if (openHeader(current, tmp, &e) != HeaderResult::Ok)
        return fail(err, e.isEmpty() ? QObject::tr("La contraseña actual no es correcta.") : e);
    unsigned char salt[kSalt];
    randombytes_buf(salt, sizeof salt);
    SecretKey kek;
    if (crypto_pwhash(kek.data(), kKey, next.constData(), static_cast<unsigned long long>(next.size()), salt, kOps,
                      static_cast<std::size_t>(kMem), crypto_pwhash_ALG_ARGON2ID13) != 0)
        return fail(err, QObject::tr("No hay memoria suficiente para derivar la clave."));
    if (!writeHeader(salt, kOps, kMem, kek)) return fail(err, QObject::tr("No se pudo guardar la nueva contraseña."));
    return true;
}

bool Vault::saveSettings() {
    if (!unlocked_) return false;
    const bool ok = saveIndex();
    const LockState old = readState();
    LockState st = stateFromSettings();
    st.fails = old.fails;
    st.lastFail = old.lastFail;
    writeState(st);
    return ok;
}

void Vault::destroyEverything(const Progress& prog) {
    const int n = std::max(1, passes());
    lock();
    const QDir d(dir_);

    // 1) Primero las claves (cabecera e índice): sin ellas el resto ya es ruido indescifrable.
    const QStringList keys = {kHeaderFile, kHeaderFile + kTmpSuffix, kIndexFile, kIndexFile + kTmpSuffix};
    for (const QString& k : keys) shredFile(d.filePath(k), n);

    // 2) Después todo lo demás (los archivos cifrados).
    const QStringList rest = d.entryList(QDir::Files | QDir::Hidden | QDir::System);
    const qint64 total = rest.size();
    qint64 done = 0;
    for (const QString& f : rest) {
        if (f == kStateFile) continue;
        shredFile(d.filePath(f), n);
        if (prog) prog(++done, total);
    }
    shredFile(statePath(), 1);
    QDir(dir_).removeRecursively();
    if (prog) prog(total, total);
}

// --- árbol de archivos -------------------------------------------------------------------------

int Vault::indexOf(const QString& id) const {
    for (std::size_t i = 0; i < items_.size(); ++i)
        if (items_[i].id == id) return int(i);
    return -1;
}

void Vault::collect(const QString& id, QStringList& out) const {
    out << id;
    for (const VaultItem& it : items_)
        if (it.parentId == id) collect(it.id, out);
}

QList<VaultEntry> Vault::children(const QString& parentId) const {
    QList<VaultEntry> out;
    for (const VaultItem& it : items_)
        if (it.parentId == parentId) out.append(static_cast<const VaultEntry&>(it));
    std::sort(out.begin(), out.end(), [](const VaultEntry& a, const VaultEntry& b) {
        if (a.isFolder != b.isFolder) return a.isFolder;
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
    return out;
}

bool Vault::entry(const QString& id, VaultEntry* out) const {
    const int i = indexOf(id);
    if (i < 0) return false;
    if (out) *out = static_cast<const VaultEntry&>(items_[std::size_t(i)]);
    return true;
}

QString Vault::pathOf(const QString& id) const {
    QStringList parts;
    QString cur = id;
    for (int guard = 0; !cur.isEmpty() && guard < 256; ++guard) {
        const int i = indexOf(cur);
        if (i < 0) break;
        parts.prepend(items_[std::size_t(i)].name);
        cur = items_[std::size_t(i)].parentId;
    }
    return parts.isEmpty() ? QString() : QStringLiteral("/") + parts.join(QLatin1Char('/'));
}

bool Vault::validName(const QString& n) {
    const QString t = n.trimmed();
    return !t.isEmpty() && t.size() <= 255 && t != QLatin1String(".") && t != QLatin1String("..") &&
           !t.contains(QLatin1Char('/')) && !t.contains(QLatin1Char('\\'));
}

QString Vault::uniqueName(const QString& parentId, const QString& name, const QString& ignoreId) const {
    auto taken = [&](const QString& cand) {
        for (const VaultItem& it : items_)
            if (it.parentId == parentId && it.id != ignoreId && it.name.compare(cand, Qt::CaseInsensitive) == 0)
                return true;
        return false;
    };
    if (!taken(name)) return name;
    const QFileInfo fi(name);
    const QString base = fi.completeBaseName().isEmpty() ? name : fi.completeBaseName();
    const QString suf = fi.suffix().isEmpty() ? QString() : QStringLiteral(".") + fi.suffix();
    for (int i = 2;; ++i) {
        const QString cand = QStringLiteral("%1 (%2)%3").arg(base).arg(i).arg(suf);
        if (!taken(cand)) return cand;
    }
}

QString Vault::createFolder(const QString& name, const QString& parentId, QString* err) {
    if (!unlocked_) {
        fail(err, QObject::tr("La bóveda está bloqueada."));
        return {};
    }
    if (!validName(name)) {
        fail(err, QObject::tr("Nombre no válido."));
        return {};
    }
    VaultItem it;
    it.id = randomId();
    it.parentId = parentId;
    it.name = uniqueName(parentId, name.trimmed(), QString());
    it.isFolder = true;
    it.modified = QDateTime::currentSecsSinceEpoch();
    items_.push_back(it);
    if (!saveIndex()) {
        items_.pop_back();
        fail(err, QObject::tr("No se pudo guardar el índice."));
        return {};
    }
    return it.id;
}

bool Vault::rename(const QString& id, const QString& newName, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const int i = indexOf(id);
    if (i < 0) return fail(err, QObject::tr("Elemento inexistente."));
    if (!validName(newName)) return fail(err, QObject::tr("Nombre no válido."));
    VaultItem& it = items_[std::size_t(i)];
    it.name = uniqueName(it.parentId, newName.trimmed(), id);
    return saveIndex() || fail(err, QObject::tr("No se pudo guardar el índice."));
}

bool Vault::importFile(const QString& src, const QString& parentId, const Progress& prog, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const QFileInfo fi(src);
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly))
        return fail(err, QObject::tr("No se pudo leer «%1».").arg(fi.fileName()));

    VaultItem it;
    it.id = randomId();
    it.parentId = parentId;
    it.name = uniqueName(parentId, fi.fileName(), QString());
    it.size = fi.size();
    it.modified = fi.lastModified().toSecsSinceEpoch();
    randombytes_buf(it.key.data(), it.key.size());

    const QString blob = blobPath(it.id);
    bool ok = false;
    {
        QFile out(blob);
        if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            ok = encryptStream(in, out, it.key.data(), it.size, prog);
            syncFile(out);
        }
    }
    if (!ok) {
        shredFile(blob, 1);
        sodium_memzero(it.key.data(), it.key.size());
        return fail(err, QObject::tr("Error al cifrar «%1».").arg(fi.fileName()));
    }
    items_.push_back(it);
    if (!saveIndex()) {
        items_.pop_back();
        shredFile(blob, 1);
        return fail(err, QObject::tr("No se pudo guardar el índice."));
    }
    sodium_memzero(it.key.data(), it.key.size());
    return true;
}

bool Vault::exportItem(const QString& id, const QString& destDir, const Progress& prog, QString* err) const {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const int i = indexOf(id);
    if (i < 0) return fail(err, QObject::tr("Elemento inexistente."));
    const VaultItem& it = items_[std::size_t(i)];

    if (it.isFolder) {
        const QString sub = safeFileName(it.name);
        QDir d(destDir);
        if (!d.mkpath(sub)) return fail(err, QObject::tr("No se pudo crear la carpeta de destino."));
        const QString subPath = d.filePath(sub);
        for (const VaultEntry& c : children(id))
            if (!exportItem(c.id, subPath, prog, err)) return false;
        return true;
    }

    QFile in(blobPath(it.id));
    if (!in.open(QIODevice::ReadOnly)) return fail(err, QObject::tr("Falta el archivo cifrado de «%1».").arg(it.name));
    const QString outPath = uniquePath(QDir(destDir).filePath(safeFileName(it.name)));
    bool ok = false;
    {
        QFile out(outPath);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return fail(err, QObject::tr("No se pudo escribir en el destino."));
        ok = decryptStream(in, out, it.key.data(), it.size, prog);
    }
    if (!ok) {
        QFile::remove(outPath);
        return fail(err, QObject::tr("«%1» está dañado o fue manipulado.").arg(it.name));
    }
    return true;
}

bool Vault::remove(const QString& id, const Progress& prog, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    QStringList ids;
    collect(id, ids);
    QStringList blobs;
    for (const QString& x : ids) {
        const int i = indexOf(x);
        if (i < 0) continue;
        VaultItem& it = items_[std::size_t(i)];
        if (!it.isFolder) blobs << it.id;
        sodium_memzero(it.key.data(), it.key.size());
        items_.erase(items_.begin() + i);
    }
    // 1) La clave de cada archivo desaparece con el índice nuevo; 2) después se destruyen los datos cifrados.
    if (!saveIndex()) return fail(err, QObject::tr("No se pudo actualizar el índice."));
    qint64 done = 0;
    for (const QString& b : blobs) {
        shredFile(blobPath(b), settings_.shredPasses);
        if (prog) prog(++done, blobs.size());
    }
    return true;
}

// --- borrado seguro ----------------------------------------------------------------------------

void Vault::shredFile(const QString& path, int passes) {
    const QFileInfo fi(path);
    if (!fi.exists()) return;
    QFile f(path);
    f.setPermissions(f.permissions() | QFileDevice::WriteOwner | QFileDevice::WriteUser);
    if (f.open(QIODevice::ReadWrite)) {
        const qint64 size = f.size();
        QByteArray buf(int(std::max<qint64>(1, std::min<qint64>(size, kChunk))), '\0');
        for (int p = 0; p < std::max(1, passes); ++p) {
            f.seek(0);
            qint64 left = size;
            while (left > 0) {
                const qint64 n = std::min<qint64>(left, buf.size());
                randombytes_buf(buf.data(), std::size_t(n));
                if (f.write(buf.constData(), n) != n) break;
                left -= n;
            }
            syncFile(f);
        }
        f.resize(0);
        syncFile(f);
        f.close();
    }
    // Renombrar a un nombre aleatorio antes de borrar: no queda rastro del nombre en el directorio.
    const QString scrambled = fi.dir().filePath(randomId());
    QFile::remove(QFile::rename(path, scrambled) ? scrambled : path);
}

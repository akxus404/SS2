#pragma once

// Estimador de fortaleza de contraseñas (heurístico, sin diccionarios externos).

#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <algorithm>
#include <cmath>

namespace Strength {

enum class Level { Empty, Weak, Medium, Strong, VeryStrong };

inline double entropyBits(const QString& pw) {
    if (pw.isEmpty()) return 0.0;

    bool lo = false, up = false, di = false, sy = false, ot = false;
    for (const QChar ch : pw) {
        const ushort u = ch.unicode();
        if (u >= 'a' && u <= 'z') lo = true;
        else if (u >= 'A' && u <= 'Z') up = true;
        else if (u >= '0' && u <= '9') di = true;
        else if (u < 128) sy = true;
        else ot = true;
    }
    const int pool = (lo ? 26 : 0) + (up ? 26 : 0) + (di ? 10 : 0) + (sy ? 33 : 0) + (ot ? 64 : 0);
    double bits = double(pw.size()) * std::log2(double(std::max(pool, 2)));

    // Caracteres repetidos
    QSet<QChar> uniq;
    for (const QChar ch : pw) uniq.insert(ch);
    bits *= 0.4 + 0.6 * double(uniq.size()) / double(pw.size());

    // Secuencias (abc, 321, ...)
    int seq = 0, run = 1, prev = 0;
    for (qsizetype i = 1; i < pw.size(); ++i) {
        const int d = int(pw[i].unicode()) - int(pw[i - 1].unicode());
        if ((d == 1 || d == -1) && (run == 1 || d == prev)) {
            prev = d;
            ++run;
        } else {
            if (run >= 3) seq += run;
            run = (d == 1 || d == -1) ? 2 : 1;
            prev = (run == 2) ? d : 0;
        }
    }
    if (run >= 3) seq += run;
    bits -= seq * 3.0;

    // Palabras y patrones muy comunes
    static const char* const kCommon[] = {"password", "contrasena", "123456", "qwerty", "admin", "letmein",
                                          "iloveyou", "welcome", "abc123", "secure", "boveda", "vault",
                                          "secret", "dragon", "master", "login", "1q2w3e", "asdf", "zxcv",
                                          "qazwsx", "football", "monkey"};
    const QString low = pw.toLower();
    for (const char* w : kCommon) {
        if (low.contains(QLatin1String(w))) {
            bits -= 20.0;
            break;
        }
    }

    // "Palabra" + pocos dígitos/símbolos (Contraseña123, hola2024!)
    static const QRegularExpression wordLike(QStringLiteral("^\\p{Lu}?\\p{Ll}{1,13}([\\d\\W_]{0,4})$"));
    const QRegularExpressionMatch m = wordLike.match(pw);
    if (m.hasMatch()) {
        const int suffix = int(m.capturedLength(1));
        const int letters = int(pw.size()) - suffix;
        bits = std::min(bits, letters * 2.2 + suffix * 3.3);
    }

    if (pw.size() < 8) bits = std::min(bits, 35.0);
    return std::max(0.0, bits);
}

inline Level classify(const QString& pw) {
    if (pw.isEmpty()) return Level::Empty;
    const double b = entropyBits(pw);
    if (b < 45.0) return Level::Weak;
    if (b < 65.0) return Level::Medium;
    if (b < 90.0) return Level::Strong;
    return Level::VeryStrong;
}

}  // namespace Strength

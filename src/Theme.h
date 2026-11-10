#pragma once

#include <QColor>
#include <QIcon>
#include <QRectF>
#include <QString>
#include <QWidget>

class QPainter;

namespace Theme {

// Paleta construida alrededor de #1e223d (kBase).
inline constexpr QRgb kBg0 = 0x14172b;       // fondo más profundo
inline constexpr QRgb kBase = 0x1e223d;      // color principal
inline constexpr QRgb kPanel = 0x272c4f;     // paneles / botones
inline constexpr QRgb kRaised = 0x323862;    // hover / relieve
inline constexpr QRgb kBorder = 0x3d4478;    // bordes
inline constexpr QRgb kText = 0xe6e8f5;      // texto
inline constexpr QRgb kDim = 0x9aa0c7;       // texto secundario
inline constexpr QRgb kAccent = 0x6c7bff;    // acento índigo
inline constexpr QRgb kAccentHi = 0x8b98ff;  // acento claro
inline constexpr QRgb kOk = 0x3ddc97;
inline constexpr QRgb kCyan = 0x4de3ff;
inline constexpr QRgb kWarn = 0xffb454;
inline constexpr QRgb kDanger = 0xff4d6d;

QString hex(QRgb color);
QString styleSheet(int fontPx = 13);
void paintLogo(QPainter& p, const QRectF& r);  // logo "SS" con forma de puerta de bóveda
QIcon appIcon();

}  // namespace Theme

class LogoWidget : public QWidget {
public:
    explicit LogoWidget(int size, QWidget* parent = nullptr);

protected:
    void paintEvent(QPaintEvent*) override;
};

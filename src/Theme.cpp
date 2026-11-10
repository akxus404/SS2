#include "Theme.h"

#include <QFont>
#include <QLinearGradient>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <algorithm>
#include <utility>

namespace Theme {

QString hex(QRgb color) { return QColor(color).name(); }

QString styleSheet(int fontPx) {
    QString s = QStringLiteral(R"QSS(
QWidget { background-color: @base@; color: @text@; font-family: "Segoe UI", "Inter", "Noto Sans", "Helvetica Neue", sans-serif; font-size: @fs@px; }
QDialog, QMainWindow { background-color: @base@; }
QLabel { background: transparent; }
QLabel#title { font-size: 22px; font-weight: 700; }
QLabel#subtitle, QLabel#hint { color: @dim@; }
QLabel#error { color: @danger@; }
QLineEdit, QSpinBox, QComboBox { background-color: @bg0@; border: 1px solid @border@; border-radius: 8px; padding: 8px 10px; selection-background-color: @accent@; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid @accent@; }
QComboBox QAbstractItemView { background-color: @bg0@; border: 1px solid @border@; selection-background-color: @accent@; }
QPushButton { background-color: @panel@; border: 1px solid @border@; border-radius: 8px; padding: 8px 16px; }
QPushButton:hover { background-color: @raised@; }
QPushButton:pressed { background-color: @bg0@; }
QPushButton:disabled { color: @dim@; background-color: @base@; }
QPushButton#primary { background-color: @accent@; border: none; color: white; font-weight: 600; }
QPushButton#primary:hover { background-color: @accenthi@; }
QPushButton#primary:disabled { background-color: @raised@; color: @dim@; }
QPushButton#danger { background-color: transparent; border: 1px solid @danger@; color: @danger@; font-weight: 600; }
QPushButton#danger:hover { background-color: @danger@; color: white; }
QTreeWidget { background-color: @bg0@; border: 1px solid @border@; border-radius: 10px; alternate-background-color: @base@; outline: 0; }
QTreeWidget::item { padding: 7px 4px; }
QTreeWidget::item:selected { background-color: @accent@; color: white; }
QTreeWidget::item:hover:!selected { background-color: @panel@; }
QHeaderView::section { background-color: @bg0@; color: @dim@; border: none; border-bottom: 1px solid @border@; padding: 8px; font-weight: 600; }
QProgressBar { background-color: @bg0@; border: 1px solid @border@; border-radius: 6px; text-align: center; }
QProgressBar::chunk { background-color: @accent@; border-radius: 5px; }
QCheckBox { spacing: 8px; background: transparent; }
QCheckBox::indicator { width: 18px; height: 18px; border-radius: 5px; border: 1px solid @border@; background-color: @bg0@; }
QCheckBox::indicator:checked { background-color: @accent@; border-color: @accent@; }
QTabWidget::pane { border: 1px solid @border@; border-radius: 10px; top: -1px; }
QTabBar::tab { background: transparent; padding: 9px 18px; color: @dim@; }
QTabBar::tab:selected { color: @text@; border-bottom: 2px solid @accent@; }
QGroupBox { border: 1px solid @border@; border-radius: 10px; margin-top: 14px; padding: 16px 10px 10px 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: @dim@; }
QStatusBar { background-color: @bg0@; color: @dim@; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background-color: @raised@; border-radius: 5px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QToolTip { background-color: @panel@; color: @text@; border: 1px solid @border@; padding: 4px; }
)QSS");

    const std::pair<const char*, QRgb> map[] = {
        {"@bg0@", kBg0},       {"@base@", kBase},       {"@panel@", kPanel}, {"@raised@", kRaised},
        {"@border@", kBorder}, {"@text@", kText},       {"@dim@", kDim},     {"@accenthi@", kAccentHi},
        {"@accent@", kAccent}, {"@danger@", kDanger},
    };
    for (const auto& kv : map) s.replace(QLatin1String(kv.first), hex(kv.second));
    s.replace(QLatin1String("@fs@"), QString::number(std::clamp(fontPx, 10, 20)));
    return s;
}

void paintLogo(QPainter& p, const QRectF& r) {
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const double s = std::min(r.width(), r.height());
    const QPointF c = r.center();

    // Cuerpo de la puerta
    const QRectF body(c.x() - s * 0.47, c.y() - s * 0.47, s * 0.94, s * 0.94);
    QLinearGradient g(body.topLeft(), body.bottomRight());
    g.setColorAt(0.0, QColor(kRaised));
    g.setColorAt(1.0, QColor(kBg0));
    p.setPen(QPen(QColor(kAccent), s * 0.04));
    p.setBrush(g);
    p.drawRoundedRect(body, s * 0.2, s * 0.2);

    // Remaches
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(kAccentHi));
    const double off = s * 0.36, rb = s * 0.035;
    for (int sx : {-1, 1})
        for (int sy : {-1, 1}) p.drawEllipse(QPointF(c.x() + sx * off, c.y() + sy * off), rb, rb);

    // Dial central
    const double R = s * 0.30;
    p.setPen(QPen(QColor(kAccent), s * 0.035));
    p.setBrush(QColor(kBase));
    p.drawEllipse(c, R, R);
    p.setPen(QPen(QColor(kAccentHi), s * 0.022, Qt::SolidLine, Qt::RoundCap));
    for (int i = 0; i < 12; ++i) {
        p.save();
        p.translate(c);
        p.rotate(i * 30.0);
        p.drawLine(QPointF(0, -R - s * 0.045), QPointF(0, -R - s * 0.085));
        p.restore();
    }

    // Texto "SS"
    QFont f = p.font();
    f.setBold(true);
    f.setPixelSize(std::max(8, int(s * 0.27)));
    p.setFont(f);
    p.setPen(QColor(kText));
    p.drawText(QRectF(c.x() - R, c.y() - R, 2 * R, 2 * R), Qt::AlignCenter, QStringLiteral("SS"));
    p.restore();
}

QIcon appIcon() {
    QIcon icon;
    for (int sz : {32, 64, 128, 256}) {
        QPixmap pm(sz, sz);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        paintLogo(p, QRectF(0, 0, sz, sz));
        p.end();
        icon.addPixmap(pm);
    }
    return icon;
}

}  // namespace Theme

LogoWidget::LogoWidget(int size, QWidget* parent) : QWidget(parent) { setFixedSize(size, size); }

void LogoWidget::paintEvent(QPaintEvent*) {
    QPainter p(this);
    Theme::paintLogo(p, QRectF(rect()));
}

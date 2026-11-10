# Secure Space (SS)

Bóveda de archivos cifrada en C++17 (Qt 6 + libsodium). Todo lo importado se guarda cifrado y con nombres
aleatorios; al eliminar, los datos se destruyen (no van a una papelera ni quedan como archivos normales).

## Compilar

**Linux (Debian/Ubuntu)**
```
sudo apt install build-essential cmake pkg-config qt6-base-dev libsodium-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/SecureSpace
```

**Windows (vcpkg + Visual Studio / Ninja)**
```
vcpkg install qt6-base libsodium
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

**macOS**: `brew install qt libsodium cmake pkg-config` y los mismos comandos de Linux
(añade `-DCMAKE_PREFIX_PATH=$(brew --prefix qt)`).

## Estructura

| Archivo | Rol |
|---|---|
| `Vault.h/.cpp` | Núcleo: claves, índice cifrado, importar/exportar, borrado seguro, destrucción total |
| `AuthDialogs.h/.cpp` | Primer inicio (crear contraseña + medidor), acceso, cambio de contraseña |
| `MainWindow.h/.cpp` | Gestor de archivos (carpetas, arrastrar y soltar, bloqueo automático) |
| `SettingsDialog.h/.cpp` | Configuración: seguridad, privacidad, general |
| `Strength.h` | Medidor Débil / Intermedia / Segura / Súper segura |
| `Theme.h/.cpp` | Paleta basada en `#1e223d`, hoja de estilos y logo "SS" (puerta de bóveda) dibujado por código |

## Diseño criptográfico

- Contraseña → **Argon2id** (256 MiB, 3 pasadas) → clave que envuelve una **clave maestra aleatoria** (`cfg.bin`).
- Cada archivo se cifra con su **propia clave aleatoria** (XChaCha20-Poly1305 en bloques de 1 MiB, con detección
  de manipulación y truncado). Las claves viven en el **índice cifrado** (`ix.bin`), con relleno a 4 KiB.
- En disco solo hay: `cfg.bin`, `ix.bin`, `st.bin` (contador de intentos) y blobs de nombre aleatorio sin extensión.
  La carpeta es oculta (`.sscache`; atributo «oculto» en Windows). Variable `SS_VAULT_DIR` para moverla (p. ej. a un USB).
- **Eliminar**: la entrada y su clave salen del índice → se sobrescribe el blob (1/3/7 pasadas) → se trunca →
  se renombra al azar → se borra.
- **Destruir todo**: primero se destruyen cabecera e índice (las claves), luego todos los blobs, y se elimina la
  carpeta. El programa vuelve a la pantalla de primer inicio.
- Las claves en RAM usan `sodium_malloc` y se borran al bloquear.

## Límites que conviene conocer

- En **SSD, sistemas de archivos con copia-al-escribir (APFS, btrfs, ZFS) o con journaling**, sobrescribir no
  garantiza físicamente que no queden restos. Por eso el diseño no depende solo de eso: lo que queda en el
  disco es texto cifrado con claves aleatorias que ya no existen en ningún sitio útil. Para máxima seguridad,
  usa cifrado de disco completo (BitLocker / LUKS / FileVault) además de SS.
- El **límite de intentos** protege contra quien use el programa. Quien copie la carpeta y ataque offline no
  pasa por el contador: ahí protege Argon2id **si la contraseña es fuerte**.
- SS no puede ocultarse de un administrador/root ni de malware con acceso a la memoria mientras la bóveda está abierta.
- Los archivos **exportados** quedan sin cifrar fuera de la bóveda.
- «Destruir original al importar» borra el original con el mismo método (mismas limitaciones en SSD).
- Primera versión: **no probada en compilación** en el entorno donde se escribió; es posible que haya que
  corregir algún detalle menor de API al compilar con tu versión de Qt.

# Fuzzing del RX LoRa con AFL++

Este documento describe cómo compilar y ejecutar un harness C/C++ para fuzzear la cadena RX de `gr-lora_sdr` usando AFL++.

El harness está en:

```bash
fuzz/afl_lora_rx_harness.cc
```

## Qué valida

El bloque jerárquico `lora_sdr_lora_rx` existe en Python, así que el harness C/C++ recrea la cadena RX con los bloques C++ públicos:

```text
vector_source_c
  -> frame_sync
  -> fft_demod
  -> gray_mapping
  -> deinterleaver
  -> hamming_dec
  -> header_decoder
  -> dewhitening
  -> crc_verif
```

AFL++ muta archivos de entrada. El harness interpreta cada entrada así:

```text
byte 0              bits de configuración
byte 1              payload length para modo implicit header
bytes restantes     muestras IQ int8 intercaladas: I,Q,I,Q,...
```

El objetivo principal es encontrar crashes, aborts, lecturas fuera de rango, escrituras fuera de rango y hangs en la cadena RX al recibir muestras corruptas o inesperadas. Para alcanzar estados más profundos, agrega al corpus capturas IQ de tramas LoRa válidas.

## Instalar AFL++

macOS con Homebrew:

```bash
brew install aflplusplus
```

Linux Debian/Ubuntu:

```bash
sudo apt update
sudo apt install afl++
```

Verifica:

```bash
afl-fuzz -V
afl-clang-fast++ --version
```

## Compilar la librería instrumentada

Desde la raíz del repo:

```bash
cd /Users/astrobyte/Tools/gr-lora_sdr
mkdir -p build-afl
CC=afl-clang-fast CXX=afl-clang-fast++ cmake \
  -S . \
  -B build-afl \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_PYTHON=OFF \
  -DENABLE_GRC=OFF \
  -DENABLE_DOXYGEN=OFF
cmake --build build-afl -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
```

`ENABLE_PYTHON=OFF` evita depender de `pybind11` para este target. El harness usa únicamente la API C++.

## Compilar el harness AFL++

macOS/Homebrew:

```bash
afl-clang-fast++ -std=c++17 \
  -Iinclude \
  $(pkg-config --cflags gnuradio-runtime gnuradio-blocks) \
  fuzz/afl_lora_rx_harness.cc \
  -Lbuild-afl/lib \
  -lgnuradio-lora_sdr \
  $(pkg-config --libs gnuradio-runtime gnuradio-blocks) \
  -o build-afl/afl_lora_rx_harness
```

Linux normalmente usa el mismo comando. Si tu instalación de GNU Radio no publica `pkg-config`, reemplaza `$(pkg-config ...)` por las rutas `-I`, `-L` y `-l` correspondientes.

Si modificas `fuzz/afl_lora_rx_harness.cc`, vuelve a ejecutar este comando antes de lanzar `afl-fuzz`.

## Smoke test

macOS:

```bash
DYLD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness fuzz/corpus/minimal_iq.seed
```

Linux:

```bash
LD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness fuzz/corpus/minimal_iq.seed
```

El smoke test debe terminar con código `0` y sin salida. Si falla por librería no encontrada, instala el proyecto o ajusta `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`.

## Ejecutar AFL++

macOS:

```bash
DYLD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -i fuzz/corpus \
  -o fuzz/out \
  -- ./build-afl/afl_lora_rx_harness @@
```

Linux:

```bash
LD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -i fuzz/corpus \
  -o fuzz/out \
  -- ./build-afl/afl_lora_rx_harness @@
```

Para una corrida inicial corta:

```bash
AFL_EXIT_WHEN_DONE=1 DYLD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -i fuzz/corpus \
  -o fuzz/out-smoke \
  -V 60 \
  -- ./build-afl/afl_lora_rx_harness @@
```

En Linux cambia `DYLD_LIBRARY_PATH` por `LD_LIBRARY_PATH`.

## Error por `core_pattern`

Si AFL++ aborta con un mensaje como:

```text
PROGRAM ABORT : Pipe at the beginning of 'core_pattern'
```

no es un error del harness. Linux está configurado para enviar core dumps a una utilidad externa como `apport` o `systemd-coredump`, y AFL++ no puede clasificar crashes de forma confiable.

Para una corrida rápida donde aceptas que AFL++ puede perder algún crash, usa:

```bash
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
LD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -i fuzz/corpus \
  -o fuzz/out \
  -- ./build-afl/afl_lora_rx_harness @@
```

Para fuzzing serio, cambia temporalmente `core_pattern`:

```bash
cat /proc/sys/kernel/core_pattern
sudo sh -c 'echo core > /proc/sys/kernel/core_pattern'
```

Después ejecuta AFL++ normalmente:

```bash
LD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -i fuzz/corpus \
  -o fuzz/out \
  -- ./build-afl/afl_lora_rx_harness @@
```

Cuando termines, restaura el valor original si lo necesitas. En Ubuntu suele ser algo parecido a:

```bash
sudo sh -c 'echo "|/usr/share/apport/apport %p %s %c %d %P %E" > /proc/sys/kernel/core_pattern'
```

También puedes guardar antes el valor exacto:

```bash
cat /proc/sys/kernel/core_pattern > /tmp/core_pattern.backup
sudo sh -c 'echo core > /proc/sys/kernel/core_pattern'
```

y restaurarlo al final:

```bash
sudo sh -c "cat /tmp/core_pattern.backup > /proc/sys/kernel/core_pattern"
```

## Error por timeout en dry-run

Si AFL++ aborta durante el dry-run con:

```text
PROGRAM ABORT : Test case ... results in a timeout
```

primero recompila el harness. El harness descarta entradas que no contienen al menos un símbolo LoRa completo para que los seeds mínimos terminen rápido:

```bash
afl-clang-fast++ -std=c++17 \
  -Iinclude \
  $(pkg-config --cflags gnuradio-runtime gnuradio-blocks) \
  fuzz/afl_lora_rx_harness.cc \
  -Lbuild-afl/lib \
  -lgnuradio-lora_sdr \
  $(pkg-config --libs gnuradio-runtime gnuradio-blocks) \
  -o build-afl/afl_lora_rx_harness
```

Prueba el seed problemático fuera de AFL++:

```bash
time LD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness fuzz/corpus/minimal_iq.seed
```

Si termina rápido fuera de AFL++ pero AFL++ sigue abortando por carga de CPU, sube el timeout:

```bash
LD_LIBRARY_PATH=build-afl/lib afl-fuzz \
  -t 5000+ \
  -i fuzz/corpus \
  -o fuzz/out \
  -- ./build-afl/afl_lora_rx_harness @@
```

El sufijo `+` le permite a AFL++ manejar casos lentos sin clasificar automáticamente todo como crash. Si incluso con `-t 5000+` el dry-run se queda colgado, elimina temporalmente el seed lento del corpus y deja solo `minimal_iq.seed` hasta tener seeds IQ válidos más pequeños.

## Corpus recomendado

El repo incluye semillas mínimas:

```text
fuzz/corpus/minimal_iq.seed
fuzz/corpus/noise_iq.seed
```

Para mejorar cobertura, agrega capturas IQ de tramas válidas generadas por el TX. AFL++ funciona mucho mejor cuando el corpus inicial contiene entradas que pasan por sincronización, demodulación y decodificación.

Formato esperado para una semilla IQ:

```text
byte 0: config
byte 1: payload length
byte 2..N: I/Q int8 intercalado
```

Ejemplo conceptual:

```python
seed = bytes([0x10, payload_len]) + iq_int8_interleaved
open("fuzz/corpus/valid_sf7.seed", "wb").write(seed)
```

Bits de configuración del primer byte:

```text
bits 0..1: SF offset, 0..3 => SF7..SF10
bits 2..3: CR offset, 0..3 => CR1..CR4
bit 4:     has_crc
bit 5:     implicit_header
```

## Revisar resultados

Crashes:

```bash
ls fuzz/out/default/crashes
```

Hangs:

```bash
ls fuzz/out/default/hangs
```

Reproducir un crash:

```bash
DYLD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness fuzz/out/default/crashes/id:000000*
```

Minimizar un crash:

```bash
DYLD_LIBRARY_PATH=build-afl/lib afl-tmin \
  -i fuzz/out/default/crashes/id:000000* \
  -o fuzz/crash-min.seed \
  -- ./build-afl/afl_lora_rx_harness @@
```

## Sanitizers

Para investigar una falla concreta, compila una versión con ASAN/UBSAN:

```bash
mkdir -p build-asan
CC=clang CXX=clang++ cmake \
  -S . \
  -B build-asan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_PYTHON=OFF \
  -DENABLE_GRC=OFF \
  -DENABLE_DOXYGEN=OFF \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
```

Compila el harness con las mismas flags:

```bash
clang++ -std=c++17 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Iinclude \
  $(pkg-config --cflags gnuradio-runtime gnuradio-blocks) \
  fuzz/afl_lora_rx_harness.cc \
  -Lbuild-asan/lib \
  -lgnuradio-lora_sdr \
  $(pkg-config --libs gnuradio-runtime gnuradio-blocks) \
  -o build-asan/afl_lora_rx_harness_asan
```

Reproduce:

```bash
DYLD_LIBRARY_PATH=build-asan/lib ./build-asan/afl_lora_rx_harness_asan fuzz/crash-min.seed
```

## Notas prácticas

- AFL++ está buscando robustez del RX ante entradas malformadas; no reemplaza las pruebas funcionales de roundtrip TX/RX.
- Usa semillas IQ válidas para aumentar cobertura real dentro de `frame_sync` y los decodificadores.
- Si GNU Radio intenta crear buffers temporales y el entorno restringe `/var/tmp`, ejecuta AFL++ fuera del sandbox o ajusta la configuración de buffers de GNU Radio de tu sistema.
- En macOS, `DYLD_LIBRARY_PATH` puede ser necesario si no instalas la librería.

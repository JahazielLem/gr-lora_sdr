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


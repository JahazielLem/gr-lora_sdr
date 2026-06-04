# Fuzzing del bloque LoRa RX

Este documento describe cómo recrear, compilar y ejecutar un fuzzer para validar el bloque jerárquico `lora_sdr_lora_rx`.

El fuzzer está en:

```bash
scripts/fuzz_lora_rx.py
```

## Qué valida

El harness crea un flowgraph por caso:

```text
PMT u8vector payload -> LoRa TX -> channel_model -> LoRa RX -> RX bytes port
```

Para cada caso genera un payload binario aleatorio, lo inyecta al TX como `PMT u8vector`, espera el mensaje del puerto `bytes` del RX y compara byte a byte:

```text
payload_tx == payload_rx
```

Esto valida el flujo de modulación y demodulación sin convertir el payload a string hexadecimal.

## Requisitos

Necesitas GNU Radio y las dependencias normales del OOT module.

En macOS con Homebrew, normalmente:

```bash
brew install gnuradio cmake pkg-config pybind11
```

En Linux, instala los paquetes equivalentes de tu distribución:

```bash
sudo apt install gnuradio-dev cmake pkg-config pybind11-dev
```

Si usas Conda o el `environment.yml` del proyecto, activa ese entorno antes de compilar.

## Compilar e instalar

Desde la raíz del repo:

```bash
cd /Users/astrobyte/Tools/gr-lora_sdr
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
sudo cmake --install build
sudo ldconfig 2>/dev/null || true
```

En macOS, si no quieres instalar en `/usr/local`, usa un prefijo local:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$HOME/.local"
cmake --build build -j"$(sysctl -n hw.ncpu)"
cmake --install build
```

Después exporta las rutas del prefijo local si GNU Radio no encuentra el módulo:

```bash
export PYTHONPATH="$HOME/.local/lib/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')/site-packages:$PYTHONPATH"
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
export GRC_BLOCKS_PATH="$HOME/.local/share/gnuradio/grc/blocks:$GRC_BLOCKS_PATH"
```

Comprueba que el módulo importa:

```bash
python3 -c "import gnuradio.lora_sdr as lora_sdr; print(lora_sdr)"
```

## Smoke test

Ejecuta pocos casos, con parámetros conservadores:

```bash
python3 scripts/fuzz_lora_rx.py \
  --cases 3 \
  --seed 1234 \
  --sf 7 \
  --cr 1 \
  --crc true \
  --implicit-header false \
  --max-len 16 \
  --timeout 5
```

Salida esperada:

```text
[*] LoRa RX fuzzing: cases=3 seed=1234
[OK] #0000 sf=7 cr=1 crc=1 implicit=0 len=...
[OK] #0001 sf=7 cr=1 crc=1 implicit=0 len=...
[OK] #0002 sf=7 cr=1 crc=1 implicit=0 len=...
[*] Summary: passed=3 failed=0 total=3
```

## Ejecución recomendada

Una corrida útil para validar variaciones de payload y configuración:

```bash
python3 scripts/fuzz_lora_rx.py \
  --cases 50 \
  --seed 2026 \
  --sf 7,8,9 \
  --cr 1,2,3,4 \
  --crc true,false \
  --implicit-header false,true \
  --bw 125000,250000 \
  --max-len 64 \
  --timeout 6 \
  --json-report artifacts/lora_rx_fuzz_report.json
```

Para detenerse en la primera falla:

```bash
python3 scripts/fuzz_lora_rx.py --cases 100 --fail-fast
```

Para agregar degradaciones de canal:

```bash
python3 scripts/fuzz_lora_rx.py \
  --cases 25 \
  --sf 7,8 \
  --snr-db 20 \
  --clk-offset-ppm 1.0
```

## Interpretación de fallas

Cada falla imprime:

```text
[FAIL] #0007 sf=8 cr=3 crc=1 implicit=0 len=...
      tx=<payload esperado en hex>
      rx=<payload recibido en hex o None>
      error=<timeout o excepción>
```

Casos comunes:

- `rx=None` y `timeout`: el RX no publicó payload antes del timeout. Sube `--timeout`, baja `--sf`, o prueba sin ruido.
- `tx != rx`: hubo corrupción o una regresión en demodulación/decodificación.
- excepción de import: el módulo no está instalado o las rutas de Python/librerías no apuntan al build instalado.

El reporte JSON guarda todos los parámetros de cada caso, por lo que cualquier falla es reproducible usando el mismo `--seed` y reduciendo `--cases` o activando `--fail-fast`.

## Parámetros principales

```bash
--cases N                 Número de casos
--seed N                  Semilla reproducible
--sf 7,8,9                Spreading factors a fuzzear
--cr 1,2,3,4              Coding rates a fuzzear
--crc true,false          Presencia de CRC
--implicit-header true,false
--bw 125000,250000        Bandwidths
--max-len N               Máximo payload en bytes
--pattern random          Patrón de payload; puede repetirse
--snr-db DB               Ruido opcional
--clk-offset-ppm PPM      Offset opcional de reloj
--json-report PATH        Reporte JSON
```

## Nota sobre payloads binarios

El fuzzer usa `pmt.init_u8vector(...)`, no `pmt.intern(payload.hex())`.

Eso permite validar bytes arbitrarios, incluyendo:

```text
0x00, 0xff, 0x80, secuencias no imprimibles y payloads que no son texto UTF-8
```


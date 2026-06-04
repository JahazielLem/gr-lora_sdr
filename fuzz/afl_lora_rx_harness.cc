/*
 * AFL++ harness for the gr-lora_sdr RX chain.
 *
 * The input file is interpreted as:
 *   byte 0: configuration bits
 *   byte 1: payload length hint for implicit header mode
 *   remaining bytes: interleaved signed 8-bit IQ samples
 *
 * This target is intended for crash/hang fuzzing. Seed it with valid IQ captures
 * to reach deeper RX states.
 */

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include <gnuradio/blocks/message_debug.h>
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/gr_complex.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/lora_sdr/crc_verif.h>
#include <gnuradio/lora_sdr/deinterleaver.h>
#include <gnuradio/lora_sdr/dewhitening.h>
#include <gnuradio/lora_sdr/fft_demod.h>
#include <gnuradio/lora_sdr/frame_sync.h>
#include <gnuradio/lora_sdr/gray_mapping.h>
#include <gnuradio/lora_sdr/hamming_dec.h>
#include <gnuradio/lora_sdr/header_decoder.h>
#include <gnuradio/top_block.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
extern "C" void __AFL_INIT(void);
#else
static inline void __AFL_INIT(void) {}
#endif

namespace {

constexpr uint32_t kCenterFreq = 868100000;
constexpr uint32_t kBandwidth = 125000;
constexpr uint8_t kOversampling = 4;
constexpr uint32_t kMaxSamples = 1u << 13;

std::vector<uint8_t> read_input(const char* path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    return { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
}

std::vector<gr_complex> bytes_to_iq(const std::vector<uint8_t>& data)
{
    std::vector<gr_complex> samples;
    if (data.size() <= 2) {
        return samples;
    }

    const size_t byte_count = std::min<size_t>(data.size() - 2, kMaxSamples * 2);
    samples.reserve(byte_count / 2);
    for (size_t i = 2; i + 1 < 2 + byte_count; i += 2) {
        const auto i_sample = static_cast<int8_t>(data[i]);
        const auto q_sample = static_cast<int8_t>(data[i + 1]);
        samples.emplace_back(static_cast<float>(i_sample) / 128.0f,
                             static_cast<float>(q_sample) / 128.0f);
    }
    return samples;
}

int run_rx_chain(const std::vector<uint8_t>& input)
{
    if (input.size() < 4) {
        return 0;
    }

    const uint8_t cfg = input[0];
    const uint8_t sf = static_cast<uint8_t>(7 + (cfg & 0x03));          // SF7..SF10
    const uint8_t cr = static_cast<uint8_t>(1 + ((cfg >> 2) & 0x03));   // CR 1..4
    const bool has_crc = ((cfg >> 4) & 0x01) != 0;
    const bool impl_head = ((cfg >> 5) & 0x01) != 0;
    const bool soft_decoding = false;
    const uint8_t ldro = 2;
    const uint32_t pay_len = std::max<uint32_t>(1, input[1]);
    const uint32_t samp_rate = kBandwidth * kOversampling;
    const std::vector<uint16_t> sync_word = { 0x12 };

    auto samples = bytes_to_iq(input);
    if (samples.empty()) {
        return 0;
    }

    const size_t samples_per_symbol = (1u << sf) * kOversampling;
    if (samples.size() < samples_per_symbol) {
        return 0;
    }

    auto tb = gr::make_top_block("afl_lora_rx_harness", true);
    auto source = gr::blocks::vector_source_c::make(samples, false);
    auto frame_sync = gr::lora_sdr::frame_sync::make(
        kCenterFreq, kBandwidth, sf, impl_head, sync_word, kOversampling, 8);
    auto fft_demod = gr::lora_sdr::fft_demod::make(soft_decoding, true);
    auto gray_mapping = gr::lora_sdr::gray_mapping::make(soft_decoding);
    auto deinterleaver = gr::lora_sdr::deinterleaver::make(soft_decoding);
    auto hamming_dec = gr::lora_sdr::hamming_dec::make(soft_decoding);
    auto header_decoder =
        gr::lora_sdr::header_decoder::make(impl_head, cr, pay_len, has_crc, ldro, false);
    auto dewhitening = gr::lora_sdr::dewhitening::make();
    auto crc_verif = gr::lora_sdr::crc_verif::make(gr::lora_sdr::crc_verif::NONE, false);
    auto byte_sink = gr::blocks::null_sink::make(sizeof(uint8_t));
    auto msg_sink = gr::blocks::message_debug::make(false);

    tb->connect(source, 0, frame_sync, 0);
    tb->connect(frame_sync, 0, fft_demod, 0);
    tb->connect(fft_demod, 0, gray_mapping, 0);
    tb->connect(gray_mapping, 0, deinterleaver, 0);
    tb->connect(deinterleaver, 0, hamming_dec, 0);
    tb->connect(hamming_dec, 0, header_decoder, 0);
    tb->connect(header_decoder, 0, dewhitening, 0);
    tb->connect(dewhitening, 0, crc_verif, 0);
    tb->connect(crc_verif, 0, byte_sink, 0);
    tb->msg_connect(header_decoder, "frame_info", frame_sync, "frame_info");
    tb->msg_connect(crc_verif, "bytes", msg_sink, "store");

    tb->run();
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <input>\n";
        return 0;
    }

    __AFL_INIT();
    const auto input = read_input(argv[1]);
    return run_rx_chain(input);
}

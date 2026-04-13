#include <benchmark/benchmark.h>
#include <random>
#include <vector>
#include <filesystem>

#include "buffer/buffer_manager.h"
#include "log/log_manager.h"
#include "storage/test_file.h"

namespace buzzdb {

class LoggingBenchmark : public benchmark::Fixture {
public:
    std::string log_file_name = "benchmark_test.log";
    std::unique_ptr<File> log_file;
    std::unique_ptr<LogManager> log_manager;
    std::unique_ptr<BufferManager> buffer_manager;

    void SetUp(const ::benchmark::State& state) {
        // Only run setup on the primary thread
        if (state.thread_index == 0) {
            if (std::filesystem::exists(log_file_name)) {
                std::filesystem::remove(log_file_name);
            }
            
            log_file = File::open_file(log_file_name.c_str(), File::WRITE);
            log_file->resize(0);
            
            log_manager = std::make_unique<LogManager>(log_file.get());
            buffer_manager = std::make_unique<BufferManager>(1024, 10); 
        }
    }

    void TearDown(const ::benchmark::State& state) {
        // Only run teardown on the primary thread
        if (state.thread_index == 0) {
            log_manager.reset();
            buffer_manager.reset();
            log_file.reset();
            if (std::filesystem::exists(log_file_name)) {
                std::filesystem::remove(log_file_name);
            }
        }
    }
};


BENCHMARK_DEFINE_F(LoggingBenchmark, SimulatedTPCCTransaction)(benchmark::State& state) {
    uint64_t txn_id = 1;
    const uint64_t update_length = 64; // Simulate 64-byte tuple updates
    std::vector<std::byte> before_img(update_length, std::byte{0});
    std::vector<std::byte> after_img(update_length, std::byte{1});

    std::mt19937 gen(42); // fixed seed
    std::uniform_int_distribution<> dist(10, 30); // Random number of updates per txn

    for (auto _ : state) {
        uint64_t current_txn = txn_id++;
        log_manager->log_txn_begin(current_txn);

        int num_updates = dist(gen);
        for (int i = 0; i < num_updates; ++i) {
            uint64_t mock_page_id = i;
            uint64_t mock_offset = 0;
            
            log_manager->log_update(
                current_txn, 
                mock_page_id, 
                update_length, 
                mock_offset, 
                before_img.data(), 
                after_img.data()
            );
        }

        log_manager->log_commit(current_txn);
    }
    
    state.SetBytesProcessed(state.iterations() * 10 * (sizeof(uint64_t) * 5 + update_length * 2)); 
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK_REGISTER_F(LoggingBenchmark, SimulatedTPCCTransaction)
    ->ThreadRange(1, 16)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(5.0)
    ->Repetitions(3)
    ->ReportAggregatesOnly(true) 
    ->UseRealTime();

} // namespace buzzdb

BENCHMARK_MAIN();
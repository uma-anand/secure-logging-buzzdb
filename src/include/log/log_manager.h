#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "buffer/buffer_manager.h"
#include "storage/test_file.h"

namespace buzzdb {

class LogManager {
   public:
    enum class LogRecordType {
        INVALID_RECORD_TYPE,
        ABORT_RECORD,
        COMMIT_RECORD,
        UPDATE_RECORD,
        BEGIN_RECORD,
        CHECKPOINT_RECORD
    };

    /// Constructor.
    LogManager(File* log_file);

    /// Destructor.
    ~LogManager();

    /// Copy Constructor
    LogManager(const LogManager& other);

    /// Copy Assignment Operator
    LogManager& operator=(const LogManager& other);

    /// Add an abort record
    void log_abort(uint64_t txn_id, BufferManager& buffer_manager);

    /// Add a commit record
    void log_commit(uint64_t txn_id);

    /// Add an update record
    void log_update(uint64_t txn_id, uint64_t page_id, uint64_t length, uint64_t offset,
                    std::byte* before_img, std::byte* after_img);

    /// Add a txn begin record
    void log_txn_begin(uint64_t txn_id);

    /// Add a log checkpoint record
    void log_checkpoint(BufferManager& buffer_manager);

    /// recovery
    void recovery(BufferManager& buffer_manager);

    /// rollback a txn
    void rollback_txn(uint64_t txn_id, BufferManager& buffer_manager);

    /// Get log records
    uint64_t get_total_log_records();

    /// Get log records of a given type
    uint64_t get_total_log_records_of_type(LogRecordType type);

    /// reset the state, used to simulate crash
    void reset(File* log_file);

   private:
    File* log_file_;
    std::mutex log_mutex_;

    // offset in the file
    size_t current_offset_ = 0;

    std::map<uint64_t, uint64_t> txn_id_to_first_log_record;

    std::map<LogRecordType, uint64_t> log_record_type_to_count;

    std::set<uint64_t> active_txns;

    template <typename T>
    void write_val(T val) {
        log_file_->write_block(reinterpret_cast<char*>(&val), current_offset_, sizeof(T));
        current_offset_ += sizeof(T);
    }

    template <typename T>
    T read_val(size_t& offset) {
        T val;
        log_file_->read_block(offset, sizeof(T), reinterpret_cast<char*>(&val));
        offset += sizeof(T);
        return val;
    }
};

}  // namespace buzzdb

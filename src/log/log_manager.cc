
#include "log/log_manager.h"

#include <string.h>

#include <cassert>
#include <cstddef>
#include <iostream>
#include <openssl/evp.h>

#include "common/macros.h"
#include "storage/test_file.h"

namespace buzzdb {

// Temporary hardcoded key and IV for prototype
const unsigned char AES_KEY[32] = {0}; // 256-bit key
const unsigned char AES_IV[12] = {0};  // 96-bit IV

// Computes H_i = MAC(Data_i || H_{i-1} || LSN_i)
std::array<unsigned char, 16> compute_gmac(
    EVP_CIPHER_CTX* ctx, 
    const std::vector<char>& data, 
    const std::array<unsigned char, 16>& prev_mac, 
    uint64_t lsn) 
{
    std::array<unsigned char, 16> out_mac = {0};
    
    // AES-256-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, AES_IV);
    
    int len;
    // 1. Data_i (The serialized log record)
    if (!data.empty()) {
        EVP_EncryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }
    // 2. H_{i-1} (The previous MAC)
    EVP_EncryptUpdate(ctx, NULL, &len, prev_mac.data(), prev_mac.size());
    // 3. LSN_i (The file offset)
    EVP_EncryptUpdate(ctx, NULL, &len, reinterpret_cast<const unsigned char*>(&lsn), sizeof(uint64_t));
    
    EVP_EncryptFinal_ex(ctx, NULL, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_mac.data());
    
    EVP_CIPHER_CTX_free(ctx);
    return out_mac;
}

/**
 * Functionality of the buffer manager that might be handy

 Flush all the dirty pages to the disk
        buffer_manager.flush_all_pages():

 Write @data of @length at an @offset the buffer page @page_id
        BufferFrame& frame = buffer_manager.fix_page(page_id, true);
        memcpy(&frame.get_data()[offset], data, length);
        buffer_manager.unfix_page(frame, true);

 * Read and Write from/to the log_file
   log_file_->read_block(offset, size, data);

   Usage:
   uint64_t txn_id;
   log_file_->read_block(offset, sizeof(uint64_t), reinterpret_cast<char *>(&txn_id));
   log_file_->write_block(reinterpret_cast<char *> (&txn_id), offset, sizeof(uint64_t));
 */

LogManager::LogManager(File* log_file) {
    log_file_ = log_file;
    log_record_type_to_count[LogRecordType::ABORT_RECORD] = 0;
    log_record_type_to_count[LogRecordType::COMMIT_RECORD] = 0;
    log_record_type_to_count[LogRecordType::UPDATE_RECORD] = 0;
    log_record_type_to_count[LogRecordType::BEGIN_RECORD] = 0;
    log_record_type_to_count[LogRecordType::CHECKPOINT_RECORD] = 0;
    stop_auditor_ = false;
    auditor_thread_ = std::thread(&LogManager::auditor_loop, this);
}

LogManager::~LogManager() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        stop_auditor_ = true;
    }
    cv_.notify_one();
    
    if (auditor_thread_.joinable()) {
        auditor_thread_.join();
    }
}

LogManager::LogManager(const LogManager& other) {
    log_file_ = other.log_file_;
    current_offset_ = other.current_offset_;
    txn_id_to_first_log_record = other.txn_id_to_first_log_record;
    log_record_type_to_count = other.log_record_type_to_count;
    active_txns = other.active_txns;
    // do not copy log_mutex_
}

LogManager& LogManager::operator=(const LogManager& other) {
    if (this != &other) {
        log_file_ = other.log_file_;
        current_offset_ = other.current_offset_;
        txn_id_to_first_log_record = other.txn_id_to_first_log_record;
        log_record_type_to_count = other.log_record_type_to_count;
        active_txns = other.active_txns;
        // do not copy log_mutex_
    }
    return *this;
}

void LogManager::reset(File* log_file) {
    log_file_ = log_file;
    current_offset_ = 0;
    txn_id_to_first_log_record.clear();
    log_record_type_to_count.clear();
    active_txns.clear();
}

void LogManager::auditor_loop(){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    while (true) {
        LogRecordBuffer record;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_.wait(lock, [this] { return !log_queue_.empty() || stop_auditor_; });
            if (stop_auditor_ && log_queue_.empty()) {
                break;
            }

            record = std::move(log_queue_.front());
            log_queue_.pop();
        }
        std::array<unsigned char, 16> mac = compute_gmac(ctx, record.data, prev_mac_, record.lsn);
        record.data.insert(record.data.end(), mac.begin(), mac.end());
        prev_mac_ = mac;
        log_file_->write_block(record.data.data(), record.lsn, record.data.size());
    }
    EVP_CIPHER_CTX_free(ctx);
}

/// Get log records
uint64_t LogManager::get_total_log_records() { 
    uint64_t total = 0;
    for (auto const& [type, count] : log_record_type_to_count) {
        total += count;
    }
    return total; 
}

uint64_t LogManager::get_total_log_records_of_type(UNUSED_ATTRIBUTE LogRecordType type) {
    return log_record_type_to_count[type];
}

/**
 * Increment the ABORT_RECORD count.
 * Rollback the provided transaction.
 * Add abort log record to the log file.
 * Remove from the active transactions.
 */
void LogManager::log_abort(uint64_t txn_id, BufferManager& buffer_manager) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_record_type_to_count[LogRecordType::ABORT_RECORD]++;
    rollback_txn(txn_id, buffer_manager);
    active_txns.erase(txn_id);

    std::vector<char> record_buffer;
    size_t exact_size = sizeof(LogRecordType) + sizeof(uint64_t) + 16;
    record_buffer.reserve(exact_size);

    auto append_to_buf = [&record_buffer](const auto& val) {
        const char* bytes = reinterpret_cast<const char*>(&val);
        record_buffer.insert(record_buffer.end(), bytes, bytes + sizeof(val));
    };

    LogRecordType type = LogRecordType::ABORT_RECORD;
    append_to_buf(type);
    append_to_buf(txn_id);

    uint64_t assigned_lsn = current_offset_;
    current_offset_ += record_buffer.size() + 16; 
    {
        std::lock_guard<std::mutex> q_lock(queue_mutex_);
        log_queue_.push({std::move(record_buffer), assigned_lsn});
    }
    cv_.notify_one();
}

/**
 * Increment the COMMIT_RECORD count
 * Add commit log record to the log file
 * Remove from the active transactions
 */
void LogManager::log_commit(uint64_t txn_id) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_record_type_to_count[LogRecordType::COMMIT_RECORD]++;
    active_txns.erase(txn_id);

    std::vector<char> record_buffer;
    size_t exact_size = sizeof(LogRecordType) + sizeof(uint64_t) + 16;
    record_buffer.reserve(exact_size);

    auto append_to_buf = [&record_buffer](const auto& val) {
        const char* bytes = reinterpret_cast<const char*>(&val);
        record_buffer.insert(record_buffer.end(), bytes, bytes + sizeof(val));
    };

    LogRecordType type = LogRecordType::COMMIT_RECORD;
    append_to_buf(type);
    append_to_buf(txn_id);

    uint64_t assigned_lsn = current_offset_;
    current_offset_ += record_buffer.size() + 16;
    {
        std::lock_guard<std::mutex> q_lock(queue_mutex_);
        log_queue_.push({std::move(record_buffer), assigned_lsn});
    }
    cv_.notify_one();
}

/**
 * Increment the UPDATE_RECORD count
 * Add the update log record to the log file
 * @param txn_id		transaction id
 * @param page_id		buffer page id
 * @param length		length of the update tuple
 * @param offset 		offset to the tuple in the buffer page
 * @param before_img	before image of the buffer page at the given offset
 * @param after_img		after image of the buffer page at the given offset
 */
void LogManager::log_update(uint64_t txn_id, uint64_t page_id,
                            uint64_t length, uint64_t offset,
                            std::byte* before_img,
                            std::byte* after_img) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_record_type_to_count[LogRecordType::UPDATE_RECORD]++;

    std::vector<char> record_buffer;
    size_t exact_size = sizeof(LogRecordType) + (sizeof(uint64_t) * 4) + (length * 2) + 16;
    record_buffer.reserve(exact_size);

    auto append_to_buf = [&record_buffer](const auto& val) {
        const char* bytes = reinterpret_cast<const char*>(&val);
        record_buffer.insert(record_buffer.end(), bytes, bytes + sizeof(val));
    };

    // Serialize everything into the buffer
    LogRecordType type = LogRecordType::UPDATE_RECORD;
    append_to_buf(type);
    append_to_buf(txn_id);
    append_to_buf(page_id);
    append_to_buf(length);
    append_to_buf(offset);

    const char* before_ptr = reinterpret_cast<const char*>(before_img);
    record_buffer.insert(record_buffer.end(), before_ptr, before_ptr + length);

    const char* after_ptr = reinterpret_cast<const char*>(after_img);
    record_buffer.insert(record_buffer.end(), after_ptr, after_ptr + length);

    uint64_t assigned_lsn = current_offset_;
    current_offset_ += record_buffer.size() + 16;

    {
        std::lock_guard<std::mutex> q_lock(queue_mutex_);
        log_queue_.push({std::move(record_buffer), assigned_lsn});
    }
    cv_.notify_one();
}

/**
 * Increment the BEGIN_RECORD count
 * Add the begin log record to the log file
 * Add to the active transactions
 */
void LogManager::log_txn_begin(UNUSED_ATTRIBUTE uint64_t txn_id) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_record_type_to_count[LogRecordType::BEGIN_RECORD]++;
    active_txns.insert(txn_id);
    if (txn_id_to_first_log_record.find(txn_id) == txn_id_to_first_log_record.end()) {
        txn_id_to_first_log_record[txn_id] = current_offset_;
    }
    
    // Buffer the record data
    std::vector<char> record_buffer;
    size_t exact_size = sizeof(LogRecordType) + sizeof(uint64_t) + 16;
    record_buffer.reserve(exact_size);
    auto append_to_buf = [&record_buffer](const auto& val) {
        const char* bytes = reinterpret_cast<const char*>(&val);
        record_buffer.insert(record_buffer.end(), bytes, bytes + sizeof(val));
    };

    LogRecordType type = LogRecordType::BEGIN_RECORD;
    append_to_buf(type);
    append_to_buf(txn_id);

    uint64_t assigned_lsn = current_offset_;
    current_offset_ += record_buffer.size() + 16;
    {
        std::lock_guard<std::mutex> q_lock(queue_mutex_);
        log_queue_.push({std::move(record_buffer), assigned_lsn});
    }
    cv_.notify_one();
}

/**
 * Increment the CHECKPOINT_RECORD count
 * Flush all dirty pages to the disk (USE: buffer_manager.flush_all_pages())
 * Add the checkpoint log record to the log file
 */
void LogManager::log_checkpoint(BufferManager& buffer_manager) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_record_type_to_count[LogRecordType::CHECKPOINT_RECORD]++;
    buffer_manager.flush_all_pages();

    std::vector<char> record_buffer;
    size_t exact_size = sizeof(LogRecordType) + sizeof(uint64_t) + (active_txns.size() * sizeof(uint64_t) * 2) + 16;
    record_buffer.reserve(exact_size);
    auto append_to_buf = [&record_buffer](const auto& val) {
        const char* bytes = reinterpret_cast<const char*>(&val);
        record_buffer.insert(record_buffer.end(), bytes, bytes + sizeof(val));
    };

    LogRecordType type = LogRecordType::CHECKPOINT_RECORD;
    append_to_buf(type);
    
    uint64_t active_count = active_txns.size();
    append_to_buf(active_count);

    for (uint64_t txn_id : active_txns) {
        append_to_buf(txn_id);
        append_to_buf(txn_id_to_first_log_record[txn_id]);
    }

    uint64_t assigned_lsn = current_offset_;
    current_offset_ += record_buffer.size() + 16;

    {
        std::lock_guard<std::mutex> q_lock(queue_mutex_);
        log_queue_.push({std::move(record_buffer), assigned_lsn});
    }
    cv_.notify_one();
}

/**
 * @Analysis Phase:
 * 		1. Get the active transactions and commited transactions
 * 		2. Restore the txn_id_to_first_log_record
 * @Redo Phase:
 * 		1. Redo the entire log tape to restore the buffer page
 * 		2. For UPDATE logs: write the after_img to the buffer page
 * 		3. For ABORT logs: rollback the transactions
 * 	@Undo Phase
 * 		1. Rollback the transactions which are active and not commited
 */
void LogManager::recovery(UNUSED_ATTRIBUTE BufferManager& buffer_manager) {
    size_t scan_offset = 0;
    std::array<unsigned char, 16> running_prev_mac = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    while (true) {
        size_t record_start_offset = scan_offset;
        LogRecordType type = LogRecordType::INVALID_RECORD_TYPE;
        log_file_->read_block(scan_offset, sizeof(LogRecordType), reinterpret_cast<char*>(&type));
        if (type == LogRecordType::INVALID_RECORD_TYPE || type < LogRecordType::ABORT_RECORD || type > LogRecordType::CHECKPOINT_RECORD) {
            break;
        }
        size_t data_size = 0;
        if (type == LogRecordType::UPDATE_RECORD) {
            // type + txn + page + len + offset
            size_t header_size = sizeof(LogRecordType) + (sizeof(uint64_t) * 4);
            uint64_t img_len;
            log_file_->read_block(record_start_offset + sizeof(LogRecordType) + (sizeof(uint64_t) * 2), sizeof(uint64_t), reinterpret_cast<char*>(&img_len));
            data_size = header_size + (img_len * 2);
        } else if (type == LogRecordType::CHECKPOINT_RECORD) {
            uint64_t active_count;
            log_file_->read_block(record_start_offset + sizeof(LogRecordType), sizeof(uint64_t), reinterpret_cast<char*>(&active_count));
            data_size = sizeof(LogRecordType) + sizeof(uint64_t) + (active_count * sizeof(uint64_t) * 2);
        } else {
            // BEGIN, COMMIT, ABORT are just Type + TxnID
            data_size = sizeof(LogRecordType) + sizeof(uint64_t);
        }

        // Read Data, Read Stored MAC, Recompute, and Compare
        std::vector<char> actual_data(data_size);
        log_file_->read_block(record_start_offset, data_size, actual_data.data());

        std::array<unsigned char, 16> stored_mac;
        log_file_->read_block(record_start_offset + data_size, 16, reinterpret_cast<char*>(stored_mac.data()));

        auto recomputed_mac = compute_gmac(ctx, actual_data, running_prev_mac, record_start_offset);
        if (recomputed_mac != stored_mac) {
            throw std::runtime_error("TAMPER DETECTION: Log integrity compromised at LSN " + std::to_string(record_start_offset));
        }
        running_prev_mac = stored_mac;

        scan_offset += sizeof(LogRecordType);
        if (type == LogRecordType::BEGIN_RECORD) {
            uint64_t txn_id = read_val<uint64_t>(scan_offset);
            active_txns.insert(txn_id);
            if (txn_id_to_first_log_record.find(txn_id) == txn_id_to_first_log_record.end()) {
                txn_id_to_first_log_record[txn_id] = scan_offset - sizeof(LogRecordType) - sizeof(uint64_t);
            }
        } 
        else if (type == LogRecordType::COMMIT_RECORD) {
            uint64_t txn_id = read_val<uint64_t>(scan_offset);
            active_txns.erase(txn_id);
        }
        else if (type == LogRecordType::ABORT_RECORD) {
            uint64_t txn_id = read_val<uint64_t>(scan_offset);
            size_t temp_offset = current_offset_;
            current_offset_ = scan_offset;
            rollback_txn(txn_id, buffer_manager);
            current_offset_ = temp_offset;
            active_txns.erase(txn_id);
        }
        else if (type == LogRecordType::UPDATE_RECORD) {
            read_val<uint64_t>(scan_offset); // move offset after trans id
            uint64_t page_id = read_val<uint64_t>(scan_offset);
            uint64_t length = read_val<uint64_t>(scan_offset);
            uint64_t offset = read_val<uint64_t>(scan_offset);

            std::vector<char> before_img(length);
            log_file_->read_block(scan_offset, length, before_img.data());
            scan_offset += length;

            std::vector<char> after_img(length);
            log_file_->read_block(scan_offset, length, after_img.data());
            scan_offset += length;

            BufferFrame& frame = buffer_manager.fix_page(page_id, true);
            memcpy(&frame.get_data()[offset], after_img.data(), length);
            buffer_manager.unfix_page(frame, true);
        }
        else if (type == LogRecordType::CHECKPOINT_RECORD) {
            uint64_t active_count = read_val<uint64_t>(scan_offset);
            for (uint64_t i = 0; i < active_count; ++i) {
                uint64_t txn_id = read_val<uint64_t>(scan_offset);
                uint64_t first_offset = read_val<uint64_t>(scan_offset);
                active_txns.insert(txn_id);
                txn_id_to_first_log_record[txn_id] = first_offset;
            }
        }
        // skip mac in scan offset
        scan_offset = record_start_offset + data_size + 16;
    }
    current_offset_ = scan_offset;
    prev_mac_ = running_prev_mac;
    EVP_CIPHER_CTX_free(ctx);
    std::set<uint64_t> txns_to_undo = active_txns;
    for (uint64_t txn_id : txns_to_undo) {
        rollback_txn(txn_id, buffer_manager);
    }
}

/**
 * Use txn_id_to_first_log_record to get the begin of the current transaction
 * Walk through the log tape and rollback the changes by writing the before
 * image of the tuple on the buffer page.
 * Note: There might be other transactions' log records interleaved, so be careful to
 * only undo the changes corresponding to current transactions.
 */
void LogManager::rollback_txn(UNUSED_ATTRIBUTE uint64_t txn_id,
                              UNUSED_ATTRIBUTE BufferManager& buffer_manager) {
    if (txn_id_to_first_log_record.find(txn_id) == txn_id_to_first_log_record.end()) {
        return; 
    }

    size_t scan_offset = txn_id_to_first_log_record[txn_id];

    struct UpdateInfo {
        uint64_t page_id;
        uint64_t length;
        uint64_t offset;
        std::vector<char> before_img;
    };
    
    std::vector<UpdateInfo> txn_updates;

    while (scan_offset < current_offset_) {
        LogRecordType type = LogRecordType::INVALID_RECORD_TYPE;
        log_file_->read_block(scan_offset, sizeof(LogRecordType), reinterpret_cast<char*>(&type));
        
        if (type == LogRecordType::INVALID_RECORD_TYPE || type < LogRecordType::ABORT_RECORD || type > LogRecordType::CHECKPOINT_RECORD) {
            break;
        }
        scan_offset += sizeof(LogRecordType);

        if (type == LogRecordType::BEGIN_RECORD || type == LogRecordType::COMMIT_RECORD || type == LogRecordType::ABORT_RECORD) {
            scan_offset += sizeof(uint64_t);
        }
        else if (type == LogRecordType::UPDATE_RECORD) {
            uint64_t current_txn_id = read_val<uint64_t>(scan_offset);
            uint64_t page_id = read_val<uint64_t>(scan_offset);
            uint64_t length = read_val<uint64_t>(scan_offset);
            uint64_t offset = read_val<uint64_t>(scan_offset);

            std::vector<char> before_img(length);
            log_file_->read_block(scan_offset, length, before_img.data());
            scan_offset += length;

            scan_offset += length; 

            if (current_txn_id == txn_id) {
                txn_updates.push_back({page_id, length, offset, before_img});
            }
        }
        else if (type == LogRecordType::CHECKPOINT_RECORD) {
            uint64_t active_count = read_val<uint64_t>(scan_offset);
            scan_offset += active_count * (sizeof(uint64_t) * 2);
        }
    }
    for (auto it = txn_updates.rbegin(); it != txn_updates.rend(); ++it) {
        BufferFrame& frame = buffer_manager.fix_page(it->page_id, true);
        memcpy(&frame.get_data()[it->offset], it->before_img.data(), it->length);
        buffer_manager.unfix_page(frame, true);
    }
}

}  // namespace buzzdb

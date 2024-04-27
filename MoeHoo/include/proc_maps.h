#ifndef PROC_MAPS_H
#define PROC_MAPS_H

#include <memory>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <functional>

#include "unistd.h"

namespace hak {
    class proc_maps: public std::enable_shared_from_this<proc_maps> {
        std::shared_ptr<proc_maps> _head;
        std::shared_ptr<proc_maps> _tail;

        uint64_t _start;
        uint64_t _end;
    public:
        proc_maps(uint64_t start, uint64_t end);

        bool readable = false;
        bool writable = false;
        bool executable = false;
        bool is_private = false;
        uint32_t offset = 0;
        std::string module_name;

        void insert(std::shared_ptr<proc_maps> maps);

        void remove();

        // The speed of this api is not very fast~~~!
        auto size() -> size_t;

        [[nodiscard]] auto start() const -> uint64_t;

        [[nodiscard]] auto end() const -> uint64_t;

        auto last() -> std::shared_ptr<proc_maps>;

        auto next() -> std::shared_ptr<proc_maps>&;
    };

    auto get_maps(pid_t pid = 0) -> std::shared_ptr<proc_maps>;
}

#endif // PROC_MAPS_H
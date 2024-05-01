#ifdef _LINUX_PLATFORM_

#include "proc_maps.h"

hak::proc_maps::proc_maps(uint64_t start, uint64_t end)
{
    this->_start = start;
    this->_end = end;
}

void hak::proc_maps::insert(std::shared_ptr<hak::proc_maps> maps)
{ // NOLINT(*-unnecessary-value-param)
    if (maps == shared_from_this())
        return;
    if (this->_tail == nullptr)
    {
        this->_tail = maps;
    }
    else
    {
        auto temp = this->_tail;
        maps->_head = shared_from_this();
        maps->last()->_tail = temp;
        this->_tail = maps;
    }
}

void hak::proc_maps::remove()
{
    _head->_tail = _tail;
    _tail->_head = _head;
}

auto hak::proc_maps::size() -> size_t
{
    size_t size = 1;
    auto curr = shared_from_this();
    while ((curr = curr->next()) != nullptr)
    {
        size++;
    }
    return size;
}

auto hak::proc_maps::start() const -> uint64_t
{
    return _start;
}

auto hak::proc_maps::end() const -> uint64_t
{
    return _end;
}

auto hak::proc_maps::next() -> std::shared_ptr<hak::proc_maps> &
{
    return _tail;
}

auto hak::proc_maps::last() -> std::shared_ptr<hak::proc_maps>
{
    auto curr = shared_from_this();
    std::shared_ptr<proc_maps> result = curr;
    while ((curr = curr->next()) != nullptr)
    {
        result = curr;
    }
    return result;
}

void llex_maps(pid_t pid, const std::function<void(std::shared_ptr<hak::proc_maps>)> &callback)
{
    std::ifstream maps(std::string("/proc/") + (pid == 0 ? std::string("self") : std::to_string(pid)) + "/maps");
    if (!maps.is_open())
        throw "maps_not_found";
    std::string line;
    bool last_is_cd = false;
    while (getline(maps, line))
    {
        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;

        while (getline(iss, token, ' '))
            tokens.push_back(token);

        auto address = tokens[0];
        std::string::size_type pos = address.find('-');
        uint64_t start_addr = std::strtoull(address.substr(0, pos), nullptr, 16);
        uint64_t end_addr = std::strtoull(address.substr(pos + 1), nullptr, 16);
        auto pmaps = std::make_shared<hak::proc_maps>(start_addr, end_addr);
        auto perms = tokens[1];
        pmaps->readable = perms[0] == 'r';
        pmaps->writable = perms[1] == 'w';
        pmaps->executable = perms[2] == 'x';
        pmaps->is_private = perms[3] == 'p';
        pmaps->offset = std::strtoull(tokens[2], nullptr, 16);
        if (tokens.size() > 5)
            for (int i = 5; i < tokens.size(); i++)
                pmaps->module_name += tokens[i];
        callback(pmaps);
    }
}

auto hak::get_maps(pid_t pid) -> std::shared_ptr<proc_maps>
{
    std::shared_ptr<proc_maps> head;
    llex_maps(pid, [&](std::shared_ptr<proc_maps> maps) { // NOLINT(*-unnecessary-value-param)
        if (head == nullptr)
            head.swap(maps);
        else
            head->insert(maps);
    });
    return head;
}

#endif